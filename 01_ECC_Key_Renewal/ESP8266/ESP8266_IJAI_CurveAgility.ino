// IJ-AI 31343 - RECONSTRUCTION LAB ONLY
// ESP8266 -> Raspberry Pi: PSK-authenticated ephemeral X25519 + HKDF-SHA256.
// LAB STAGE 3: authenticated /ack and HMAC-protected telemetry under the active session key.
// IMPORTANT: telemetry is authenticated, NOT encrypted; NO EOSIO submission.
// Requires Rhys Weatherley's Arduino Crypto library (Crypto, Curve25519, SHA256, RNG).
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <Curve25519.h>
#include <Crypto.h>
#include <SHA256.h>
#include <RNG.h>
#include <string.h>
#include <bearssl/bearssl.h>
#include <pgmspace.h>
#include "private_config.h"

const char *DEVICE_ID = "testtag1";

static char hexdigit(uint8_t x) { return x < 10 ? char('0' + x) : char('a' + x - 10); }
static String toHex(const uint8_t *p, size_t n) {
  String out; out.reserve(n * 2 + 1);
  for (size_t i = 0; i < n; ++i) { out += hexdigit(p[i] >> 4); out += hexdigit(p[i] & 15); }
  return out;
}
static int hexval(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}
static bool fromHex(const String& hex, uint8_t *p, size_t n) {
  if (hex.length() != n * 2) return false;
  for (size_t i = 0; i < n; ++i) {
    int hi = hexval(hex[2*i]), lo = hexval(hex[2*i+1]);
    if (hi < 0 || lo < 0) return false;
    p[i] = uint8_t((hi << 4) | lo);
  }
  return true;
}
static bool same32(const uint8_t *a, const uint8_t *b) {
  uint8_t diff = 0;
  for (size_t i=0; i<32; ++i) diff |= (a[i] ^ b[i]);
  return diff == 0;
}
static String jsonStr(const String& body, const char* key) {
  String needle = String('"') + key + "\"";
  int p = body.indexOf(needle);
  if (p < 0) return "";
  p = body.indexOf(':', p + needle.length());
  if (p < 0) return "";
  ++p;
  while (p < int(body.length()) && (body[p] == ' ' || body[p] == '\t')) ++p;
  if (p >= int(body.length()) || body[p] != '"') return "";
  int end = body.indexOf('"', p+1);
  if (end < 0) return "";
  return body.substring(p+1, end);
}
static void hmacSHA256(const uint8_t *key, size_t keylen, const uint8_t *data,
                       size_t datalen, uint8_t out[32]) {
  SHA256 h;
  h.resetHMAC(key, keylen);
  h.update(data, datalen);
  h.finalizeHMAC(key, keylen, out, 32);
}
static void hmacText(const uint8_t *key, size_t keylen,
                     const String& msg, uint8_t out[32]) {
  hmacSHA256(key, keylen,
             reinterpret_cast<const uint8_t*>(msg.c_str()), msg.length(), out);
}
static bool httpPost(const String& route, const String& payload, String& response, int& code) {
  WiFiClient client;
  HTTPClient http;
  const String url = String(GATEWAY_URL) + route;
  if (!http.begin(client, url)) { code=-1; return false; }
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(10000);
  code = http.POST(payload);
  if (code > 0) response = http.getString();
  else response = http.errorToString(code);
  http.end();
  return code == 200;
}
static uint8_t activeKey[32] = {0};
static uint32_t activeEpoch = 0;
static uint32_t dataCounter = 0;
static String activeSid = "";
static unsigned long epochStartedMs = 0;
static unsigned long epochLifetimeMs = 0;

static String jsonNumber(const String& body, const char *key) {
  String needle = String('"') + key + "\"";
  int p = body.indexOf(needle);
  if (p < 0) return "";
  p = body.indexOf(':', p + needle.length());
  if (p < 0) return "";
  ++p;
  while (p < int(body.length()) && (body[p] == ' ' || body[p] == '\t')) ++p;
  int start = p;
  while (p < int(body.length()) && ((body[p] >= '0' && body[p] <= '9') || body[p]=='.')) ++p;
  return p > start ? body.substring(start,p) : "";
}

static void discardActiveKey() {
  memset(activeKey, 0, sizeof(activeKey));
  activeEpoch = 0; dataCounter = 0; activeSid = "";
  epochStartedMs = 0; epochLifetimeMs = 0;
}

// ESP8266 Stage6: BearSSL P-256 key exchange, with curve order copied into RAM.
// This implements the same memory workaround tested by the 50-trial P-256 benchmark.
static constexpr int S6_CURVE = BR_EC_secp256r1;
static br_ec_impl s6EcRam;
static unsigned char s6CurveOrder[32];
static const br_ec_impl *s6Ec = nullptr;

static const unsigned char* s6OrderFromRAM(int curve, size_t* len) {
  if (curve != S6_CURVE) { *len = 0; return nullptr; }
  *len = sizeof(s6CurveOrder);
  return s6CurveOrder;
}
static bool s6InitCurve() {
  const br_ec_impl* orig = br_ec_get_default();
  if (!orig || !(orig->supported_curves & (1UL << S6_CURVE))) return false;
  size_t n=0;
  const unsigned char* orderFlash = orig->order(S6_CURVE, &n);
  if (!orderFlash || n != sizeof(s6CurveOrder)) return false;
  for (size_t i=0; i<n; ++i) s6CurveOrder[i] = pgm_read_byte(orderFlash+i);
  s6EcRam = *orig;
  s6EcRam.order = s6OrderFromRAM;
  s6Ec = &s6EcRam;
  return true;
}

static void s6Zero(void *ptr, size_t n) {
  volatile uint8_t *p = reinterpret_cast<volatile uint8_t*>(ptr);
  while (n--) *p++ = 0;
}
struct S6SecureBuffer {
  void *p; size_t n;
  ~S6SecureBuffer() { s6Zero(p,n); }
};

struct S6P256Session {
  br_hmac_drbg_context drbg;
  br_ec_private_key privateKey;
  br_ec_public_key publicKey;
  unsigned char privateBuffer[BR_EC_KBUF_PRIV_MAX_SIZE];
  unsigned char publicBuffer[BR_EC_KBUF_PUB_MAX_SIZE];
  unsigned char pointBuffer[BR_EC_KBUF_PUB_MAX_SIZE];
  bool ok=false;

  S6P256Session() {
    memset(&drbg,0,sizeof(drbg));
    memset(&privateKey,0,sizeof(privateKey));
    memset(&publicKey,0,sizeof(publicKey));
    memset(privateBuffer,0,sizeof(privateBuffer));
    memset(publicBuffer,0,sizeof(publicBuffer));
    memset(pointBuffer,0,sizeof(pointBuffer));
  }
  ~S6P256Session() {
    s6Zero(&drbg,sizeof(drbg));
    s6Zero(&privateKey,sizeof(privateKey));
    s6Zero(&publicKey,sizeof(publicKey));
    s6Zero(privateBuffer,sizeof(privateBuffer));
    s6Zero(publicBuffer,sizeof(publicBuffer));
    s6Zero(pointBuffer,sizeof(pointBuffer));
  }
  bool generate(uint8_t outPub[65]) {
    if (!s6Ec) return false;
    uint8_t seed[48];
    RNG.rand(seed,sizeof(seed));
    br_hmac_drbg_init(&drbg,&br_sha256_vtable,seed,sizeof(seed));
    s6Zero(seed,sizeof(seed));
    if (!br_ec_keygen(&drbg.vtable,s6Ec,&privateKey,privateBuffer,S6_CURVE)) return false;
    size_t n = br_ec_compute_pub(s6Ec,&publicKey,publicBuffer,&privateKey);
    if (n != 65 || publicBuffer[0] != 0x04) return false;
    memcpy(outPub,publicBuffer,65);
    ok=true;
    return true;
  }
  bool exchange(const uint8_t peer[65], uint8_t secret[32]) {
    if (!ok || !s6Ec || peer[0]!=0x04) return false;
    memcpy(pointBuffer,peer,65);
    if (s6Ec->mul(pointBuffer,65,privateKey.x,privateKey.xlen,S6_CURVE) != 1) return false;
    size_t len=0;
    size_t off=s6Ec->xoff(S6_CURVE,&len);
    if (len!=32 || off>65 || len>65-off) return false;
    uint8_t nonzero=0;
    for (size_t i=0;i<32;++i) nonzero|=pointBuffer[off+i];
    if (!nonzero) return false;
    memcpy(secret,pointBuffer+off,32);
    return true;
  }
};

// A confirmed epoch number is retained in RAM even after key expiry.
// It is NOT retained across MCU resets. Restart gateway and MCU together for lab runs.
static uint32_t lastConfirmedEpoch = 0;

static bool runHandshake() {
  if (WiFi.status()!=WL_CONNECTED) return false;
  const uint32_t started=millis();
  const uint32_t heapBefore=ESP.getFreeHeap();
  const uint32_t oldEpoch=lastConfirmedEpoch;
  const bool p256=(oldEpoch % 2u)==1u;
  const String alg=p256 ? "P256" : "X25519";
  const size_t pubLen=p256 ? 65u : 32u;

  uint8_t psk[32]={0},clientPub[65]={0},xpriv[32]={0},cnonce[16]={0};
  uint8_t serverPub[65]={0}, serverNonce[16]={0},receivedMac[32]={0};
  uint8_t salt[32]={0},prk[32]={0},sessionKey[32]={0},macClient[32]={0};
  uint8_t macKey[32]={0},shared[32]={0},expectedMac[32]={0};
  S6SecureBuffer wp{psk,sizeof(psk)}, wx{xpriv,sizeof(xpriv)};
  S6SecureBuffer ws{shared,sizeof(shared)}, wk{sessionKey,sizeof(sessionKey)};
  S6SecureBuffer wr{prk,sizeof(prk)};
  S6P256Session curve;

  if (!fromHex(String(DEVICE_PSK_HEX),psk,sizeof(psk))) {
    Serial.println("ERROR invalid PSK config"); return false;
  }
  uint32_t t=micros();
  bool generated=false;
  if (p256) generated=curve.generate(clientPub);
  else { Curve25519::dh1(clientPub,xpriv); generated=true; }
  const uint32_t dh1_us=micros()-t;
  if (!generated) { Serial.println("P256_KEYGEN_FAILED"); return false; }
  yield();
  RNG.rand(cnonce,sizeof(cnonce));
  const String cp=toHex(clientPub,pubLen), cn=toHex(cnonce,sizeof(cnonce));
  const String body1=String("{\"device_id\":\"")+DEVICE_ID+
        "\",\"algorithm\":\""+alg+
        "\",\"client_pub\":\""+cp+
        "\",\"client_nonce\":\""+cn+"\"}";
  String response; int code=0;
  if (!httpPost("/begin",body1,response,code)) {
    Serial.printf("BEGIN_FAILED http=%d reason=%s\n",code,response.c_str()); return false;
  }
  const String sid=jsonStr(response,"session_id");
  const String algReply=jsonStr(response,"algorithm");
  const String sp=jsonStr(response,"server_pub");
  const String sn=jsonStr(response,"server_nonce");
  if (sid.length()!=32 || algReply!=alg ||
      !fromHex(sp,serverPub,pubLen) ||
      !fromHex(sn,serverNonce,16) ||
      !fromHex(jsonStr(response,"server_mac"),receivedMac,32)) {
    Serial.println("BEGIN_FAILED malformed or wrong algorithm"); return false;
  }
  const String tx=String("IJAI31343-v2|")+alg+"|"+DEVICE_ID+"|"+
      cp+"|"+cn+"|"+sp+"|"+sn+"|"+sid;
  hmacText(psk,32,String("SERVER|")+tx,expectedMac);
  if (!same32(expectedMac,receivedMac)) {
    Serial.println("AUTH_FAILED server transcript/algorithm"); return false;
  }

  t=micros();
  bool exchanged=false;
  if (p256) exchanged=curve.exchange(serverPub,shared);
  else {
    exchanged=Curve25519::dh2(serverPub,xpriv);
    if (exchanged) memcpy(shared,serverPub,32);
  }
  const uint32_t dh2_us=micros()-t;
  if (!exchanged) { Serial.println("AUTH_FAILED invalid peer key"); return false; }
  yield();
  memcpy(salt,cnonce,16); memcpy(salt+16,serverNonce,16);
  hmacSHA256(salt,32,shared,32,prk);
  String info=String("IJAI31343-SESSION-V2|")+tx;
  info+=char(1);
  hmacText(prk,32,info,sessionKey);
  hmacText(psk,32,String("CLIENT|")+tx,macClient);
  hmacText(sessionKey,32,String("CLIENTKEY|")+tx,macKey);
  const String body2=String("{\"session_id\":\"")+sid+
      "\",\"client_mac\":\""+toHex(macClient,32)+
      "\",\"client_key_mac\":\""+toHex(macKey,32)+"\"}";
  response="";
  if (!httpPost("/finish",body2,response,code)) {
    Serial.printf("FINISH_FAILED http=%d reason=%s\n",code,response.c_str()); return false;
  }
  if (response.indexOf("\"authenticated\":true")==-1 ||
      jsonStr(response,"algorithm")!=alg ||
      !fromHex(jsonStr(response,"server_key_mac"),receivedMac,32)) {
    Serial.println("AUTH_FAILED malformed finish"); return false;
  }
  hmacText(sessionKey,32,String("SERVERKEY|")+tx,expectedMac);
  if (!same32(expectedMac,receivedMac)) {
    Serial.println("AUTH_FAILED server key proof"); return false;
  }

  uint8_t ackMac[32]={0};
  S6SecureBuffer wa{ackMac,sizeof(ackMac)};
  hmacText(sessionKey,32,String("DEVICE-ACK|")+tx,ackMac);
  const String body3=String("{\"session_id\":\"")+sid+
      "\",\"ack_mac\":\""+toHex(ackMac,32)+"\"}";
  response="";
  if (!httpPost("/ack",body3,response,code)) {
    Serial.printf("ACK_FAILED http=%d reason=%s\n",code,response.c_str()); return false;
  }
  const String epochText=jsonNumber(response,"epoch");
  const String ttlText=jsonNumber(response,"interval_seconds");
  const uint32_t newEpoch=(uint32_t)epochText.toInt();
  const float ttlSeconds=ttlText.toFloat();
  if (newEpoch!=oldEpoch+1u || ttlText.length()==0 ||
      ttlSeconds<1 || ttlSeconds>3600 ||
      jsonStr(response,"algorithm")!=alg ||
      !fromHex(jsonStr(response,"ack_server_mac"),receivedMac,32)) {
    Serial.println("ACK_FAILED invalid epoch/algorithm/interval"); return false;
  }
  hmacText(sessionKey,32,String("SERVER-ACK|")+tx+"|"+
           String(newEpoch)+"|"+ttlText,expectedMac);
  if (!same32(expectedMac,receivedMac)) {
    Serial.println("ACK_FAILED server activation proof"); return false;
  }

  discardActiveKey();
  memcpy(activeKey,sessionKey,32);
  activeEpoch=newEpoch;
  lastConfirmedEpoch=newEpoch;
  activeSid=sid;
  dataCounter=0;
  epochStartedMs=millis();
  epochLifetimeMs=(unsigned long)(ttlSeconds*1000.0f);
  Serial.printf("ALG=%s EPOCH_OK epoch=%lu lifetime_ms=%lu dh1_us=%lu dh2_us=%lu total_ms=%lu heap_before=%lu heap_after=%lu\n",
    alg.c_str(),(unsigned long)activeEpoch,epochLifetimeMs,
    (unsigned long)dh1_us,(unsigned long)dh2_us,
    (unsigned long)(millis()-started),
    (unsigned long)heapBefore,(unsigned long)ESP.getFreeHeap());
  Serial.println("LAB HMAC-ONLY DATA; NO DIRECT EOSIO; no AEAD");
  return true;
}

static void sendAuthenticatedData() {
  if (activeEpoch==0 || activeSid.length()!=32) return;
  if ((uint32_t)(millis()-epochStartedMs)>=epochLifetimeMs) {
    discardActiveKey(); return;
  }
  const uint32_t nextCounter=dataCounter+1;
  const int testValue=42;  // SYNTHETIC fixed test value, not actual DHT11/RFID/energy.
  String msg=String("DATA|")+DEVICE_ID+"|"+activeSid+"|"+
             String(activeEpoch)+"|"+String(nextCounter)+"|"+String(testValue);
  uint8_t tag[32]; hmacText(activeKey,32,msg,tag);
  String body=String("{\"session_id\":\"")+activeSid+
              "\",\"epoch\":"+String(activeEpoch)+
              ",\"counter\":"+String(nextCounter)+
              ",\"value\":"+String(testValue)+
              ",\"data_mac\":\""+toHex(tag,32)+"\"}";
  String response; int code=0;
  if (!httpPost("/data",body,response,code)) {
    Serial.printf("DATA_FAILED http=%d (may require rekey)\n",code);
    discardActiveKey(); return;
  }
  if (response.indexOf("\"accepted\":true")==-1) {
    Serial.println("DATA_FAILED invalid response"); discardActiveKey(); return;
  }
  dataCounter=nextCounter;
  Serial.printf("DATA_OK epoch=%lu counter=%lu value=%d (HMAC only)\n",
                (unsigned long)activeEpoch,(unsigned long)dataCounter,testValue);
}

void setup() {
  Serial.begin(115200); delay(1200);
  Serial.println("IJAI31343 STAGE6 ESP8266: AUTHENTICATED CURVE AGILITY LAB");
  WiFi.persistent(false); WiFi.mode(WIFI_STA);
  RNG.begin("IJAI31343-ESP8266-CURVE-AGILITY-v2");
  if (!s6InitCurve()) { Serial.println("P256_INIT_FAILED"); while(true) delay(1000); }
  Serial.println("P256_ORDER_IN_RAM_OK");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  const unsigned long t = millis();
  while (WiFi.status()!=WL_CONNECTED && millis()-t < 25000) {delay(500); Serial.print('.');}
  if (WiFi.status()==WL_CONNECTED) {
    Serial.printf("\nWIFI_OK ip=%s gateway=%s\n", WiFi.localIP().toString().c_str(),GATEWAY_URL);
  } else Serial.printf("\nWIFI_FAILED status=%d\n",WiFi.status());
}
void loop() {
  if (WiFi.status()!=WL_CONNECTED) {
    discardActiveKey(); WiFi.reconnect(); delay(5000); return;
  }
  if (!activeEpoch || (uint32_t)(millis()-epochStartedMs)>=epochLifetimeMs) {
    discardActiveKey();
    runHandshake();
  }
  if (activeEpoch) sendAuthenticatedData();
  RNG.loop();
  delay(5000);
}
