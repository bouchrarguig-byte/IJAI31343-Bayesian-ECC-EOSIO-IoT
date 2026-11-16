#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
// IJ-AI 31343 - RECONSTRUCTION LAB ONLY
// ESP32-D0WD-V3 -> Raspberry Pi: PSK-authenticated ephemeral X25519/P-256 + HKDF-SHA256.
// LAB STAGE 3: authenticated /ack and HMAC-protected telemetry under the active session key.
// IMPORTANT: telemetry is authenticated, NOT encrypted; NO EOSIO submission.
// Requires Rhys Weatherley's Arduino Crypto library (Crypto, Curve25519, SHA256, RNG).
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClient.h>
#include <Curve25519.h>
#include <Crypto.h>
#include <SHA256.h>
#include <RNG.h>
#include <string.h>
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

// Stage6: secure-ish cleanup for ephemeral buffers on every return path.
struct S6Wipe {
  uint8_t *p;
  size_t n;
  ~S6Wipe() { volatile uint8_t *v = p; for (size_t i=0; i<n; ++i) v[i]=0; }
};

// Local ephemeral P-256 context (Mbed TLS version verified by prior benchmark).
class S6P256 {
 public:
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_ecp_group group;
  mbedtls_mpi priv;
  mbedtls_ecp_point pub;

  S6P256() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&priv);
    mbedtls_ecp_point_init(&pub);
  }
  ~S6P256() {
    mbedtls_ecp_point_free(&pub);
    mbedtls_mpi_free(&priv);
    mbedtls_ecp_group_free(&group);
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
  }
  bool generate(uint8_t out_pub[65]) {
    static const char seed[] = "IJAI31343-Stage6-P256";
    int rc=mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,
                                 (const unsigned char*)seed,sizeof(seed)-1);
    if (rc != 0) return false;
    rc=mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) return false;
    rc=mbedtls_ecdh_gen_public(&group,&priv,&pub,mbedtls_ctr_drbg_random,&rng);
    if (rc != 0) return false;
    size_t olen=0;
    rc=mbedtls_ecp_point_write_binary(&group,&pub,
         MBEDTLS_ECP_PF_UNCOMPRESSED,&olen,out_pub,65);
    return rc==0 && olen==65 && out_pub[0]==0x04;
  }
  bool exchange(const uint8_t peer_bytes[65], uint8_t shared[32]) {
    mbedtls_ecp_point peer;
    mbedtls_mpi z;
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&z);
    int rc=mbedtls_ecp_point_read_binary(&group,&peer,peer_bytes,65);
    if (rc==0) rc=mbedtls_ecp_check_pubkey(&group,&peer);
    if (rc==0) rc=mbedtls_ecdh_compute_shared(&group,&z,&peer,&priv,
                                               mbedtls_ctr_drbg_random,&rng);
    if (rc==0 && mbedtls_mpi_bitlen(&z)>0)
      rc=mbedtls_mpi_write_binary(&z,shared,32);
    else if (rc==0) rc=-1;
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&z);
    return rc==0;
  }
};

static uint32_t lastConfirmedEpoch = 0;

static bool runHandshake() {
  if (WiFi.status() != WL_CONNECTED) return false;
  const uint32_t started=millis();
  const uint32_t heapBefore=ESP.getFreeHeap();

  // Reproducible authorized laboratory schedule, NOT risk-selected curves.
  const uint32_t oldEpoch=lastConfirmedEpoch;
  const bool isP256=(oldEpoch % 2u)==1u;
  const String alg=isP256 ? "P256" : "X25519";
  const size_t pubLen=isP256 ? 65u : 32u;

  uint8_t psk[32]={0}, clientPub[65]={0}, xpriv[32]={0}, cnonce[16]={0};
  uint8_t serverPub[65]={0}, serverNonce[16]={0}, receivedMac[32]={0};
  uint8_t salt[32]={0}, prk[32]={0}, sessionKey[32]={0}, macClient[32]={0};
  uint8_t macKey[32]={0}, shared[32]={0}, expMac[32]={0};
  S6Wipe wpsk{psk,sizeof(psk)}, wpriv{xpriv,sizeof(xpriv)};
  S6Wipe wshared{shared,sizeof(shared)}, wprk{prk,sizeof(prk)};
  S6Wipe wsess{sessionKey,sizeof(sessionKey)};
  S6P256 p256;

  if (!fromHex(String(DEVICE_PSK_HEX),psk,sizeof(psk))) {
    Serial.println("ERROR invalid PSK config"); return false;
  }

  uint32_t t=micros();
  bool keyOK=false;
  if (isP256) keyOK=p256.generate(clientPub);
  else { Curve25519::dh1(clientPub,xpriv); keyOK=true; }
  const uint32_t dh1_us=micros()-t;
  if (!keyOK) { Serial.println("P256_KEYGEN_FAILED"); return false; }
  RNG.rand(cnonce,sizeof(cnonce));
  const String cp=toHex(clientPub,pubLen);
  const String cn=toHex(cnonce,sizeof(cnonce));
  const String body1=String("{\"device_id\":\"")+DEVICE_ID+
               "\",\"algorithm\":\""+alg+
               "\",\"client_pub\":\""+cp+
               "\",\"client_nonce\":\""+cn+"\"}";
  String response; int code=0;
  if (!httpPost("/begin",body1,response,code) || code != 200) {
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
    Serial.println("BEGIN_FAILED malformed or changed algorithm"); return false;
  }
  const String tx=String("IJAI31343-v2|")+alg+"|"+DEVICE_ID+"|"+
                  cp+"|"+cn+"|"+sp+"|"+sn+"|"+sid;
  hmacText(psk,32,String("SERVER|")+tx,expMac);
  if (!same32(expMac,receivedMac)) {
    Serial.println("AUTH_FAILED server algorithm/transcript proof"); return false;
  }

  t=micros();
  bool exchangeOK=false;
  if (isP256) exchangeOK=p256.exchange(serverPub,shared);
  else {
    // Curve25519::dh2 mutates the serverPub buffer into the shared secret.
    exchangeOK=Curve25519::dh2(serverPub,xpriv);
    if (exchangeOK) memcpy(shared,serverPub,32);
  }
  const uint32_t dh2_us=micros()-t;
  if (!exchangeOK) {
    Serial.println("AUTH_FAILED invalid ECDH peer"); return false;
  }
  memcpy(salt,cnonce,16);
  memcpy(salt+16,serverNonce,16);
  hmacSHA256(salt,32,shared,32,prk);
  String info=String("IJAI31343-SESSION-V2|")+tx;
  info+=char(1);  // HKDF-Expand single block T(1).
  hmacText(prk,32,info,sessionKey);
  hmacText(psk,32,String("CLIENT|")+tx,macClient);
  hmacText(sessionKey,32,String("CLIENTKEY|")+tx,macKey);
  const String body2=String("{\"session_id\":\"")+sid+
                    "\",\"client_mac\":\""+toHex(macClient,32)+
                    "\",\"client_key_mac\":\""+toHex(macKey,32)+"\"}";
  response="";
  if (!httpPost("/finish",body2,response,code) || code != 200) {
    Serial.printf("FINISH_FAILED http=%d\n",code); return false;
  }
  if (response.indexOf("\"authenticated\":true")==-1 ||
      jsonStr(response,"algorithm")!=alg ||
      !fromHex(jsonStr(response,"server_key_mac"),receivedMac,32)) {
    Serial.println("AUTH_FAILED malformed finish"); return false;
  }
  hmacText(sessionKey,32,String("SERVERKEY|")+tx,expMac);
  if (!same32(expMac,receivedMac)) {
    Serial.println("AUTH_FAILED gateway key proof"); return false;
  }
  uint8_t ackMac[32]={0};
  hmacText(sessionKey,32,String("DEVICE-ACK|")+tx,ackMac);
  const String body3=String("{\"session_id\":\"")+sid+
                     "\",\"ack_mac\":\""+toHex(ackMac,32)+"\"}";
  response="";
  if (!httpPost("/ack",body3,response,code) || code != 200) {
    Serial.printf("ACK_FAILED http=%d\n",code); return false;
  }
  const String epochText=jsonNumber(response,"epoch");
  const String ttlText=jsonNumber(response,"interval_seconds");
  const uint32_t newEpoch=(uint32_t)epochText.toInt();
  const float ttlSeconds=ttlText.toFloat();
  if (newEpoch != oldEpoch+1u || ttlText.length()==0 ||
      ttlSeconds<1 || ttlSeconds>3600 ||
      jsonStr(response,"algorithm")!=alg ||
      !fromHex(jsonStr(response,"ack_server_mac"),receivedMac,32)) {
    Serial.println("ACK_FAILED invalid epoch/algorithm/lifetime"); return false;
  }
  hmacText(sessionKey,32,String("SERVER-ACK|")+tx+"|"+
           String(newEpoch)+"|"+ttlText,expMac);
  if (!same32(expMac,receivedMac)) {
    Serial.println("ACK_FAILED gateway activation/lifetime proof"); return false;
  }
  // Stage6: install only after the server's authenticated activation proof.
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
        (unsigned long)(millis()-started),(unsigned long)heapBefore,
        (unsigned long)ESP.getFreeHeap());
  Serial.println("LAB HMAC-ONLY DATA; EOSIO attestations via ZBook bridge");
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
  Serial.println("IJAI31343 STAGE6 ESP32: AUTHENTICATED CURVE AGILITY LAB");
  Serial.printf("PLATFORM chip=%s revision=%u cpu_mhz=%u free_heap=%u min_heap=%u\n",
                ESP.getChipModel(),
                static_cast<unsigned>(ESP.getChipRevision()),
                static_cast<unsigned>(getCpuFrequencyMhz()),
                static_cast<unsigned>(ESP.getFreeHeap()),
                static_cast<unsigned>(ESP.getMinFreeHeap()));
  WiFi.persistent(false); WiFi.mode(WIFI_STA);
  RNG.begin("IJAI31343-ESP32-X25519-v1");
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
