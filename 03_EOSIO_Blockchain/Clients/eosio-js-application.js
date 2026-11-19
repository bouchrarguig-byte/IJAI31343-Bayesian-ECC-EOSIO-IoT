'use strict';
// Reference client for the iotauth2 `authenticate` action (LAB / dev chain only).
// Secrets are read from the environment, never from a file that could be committed:
//   EOSIO_HTTP_ENDPOINT   e.g. http://127.0.0.1:8888
//   EOSIO_PRIVATE_KEY     private key of the authorizing account (dev-chain key only)
//   EOSIO_CONTRACT        contract account (iotauth2)
//   EOSIO_ACTOR           authorizing account
//   IOT_RFID_TAG          device tag
//   IOT_ORIGINAL_KEY      key material whose BLAKE2s digest is submitted
// Usage: node eosio-js-application.js
const { JsonRpc, Api } = require('eosjs');
const { JsSignatureProvider } = require('eosjs/dist/eosjs-jssig');
const fetch = require('node-fetch');
const { TextEncoder, TextDecoder } = require('util');
const Blake2s = require('blake2s-js');

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing environment variable ${name}`);
    process.exit(2);
  }
  return value;
}

const endpoint = required('EOSIO_HTTP_ENDPOINT');
const privateKey = required('EOSIO_PRIVATE_KEY');
const contractAccount = required('EOSIO_CONTRACT');
const authorizingAccount = required('EOSIO_ACTOR');
const rfidTag = required('IOT_RFID_TAG');
const originalKey = required('IOT_ORIGINAL_KEY');

const rpc = new JsonRpc(endpoint, { fetch });
const signatureProvider = new JsSignatureProvider([privateKey]);
const api = new Api({
  rpc,
  signatureProvider,
  textEncoder: new TextEncoder(),
  textDecoder: new TextDecoder(),
});

function blake2s(data) {
  const hasher = new Blake2s();
  hasher.update(Buffer.from(data, 'utf8'));
  return hasher.hexDigest();
}

async function authenticate() {
  const hashedKey = blake2s(originalKey);
  const result = await api.transact(
    {
      actions: [{
        account: contractAccount,
        name: 'authenticate',
        authorization: [{ actor: authorizingAccount, permission: 'active' }],
        data: { rfid_tag: rfidTag, key: hashedKey },
      }],
    },
    { blocksBehind: 3, expireSeconds: 30 },
  );
  console.log('Authentication transaction accepted:', result.transaction_id);
}

authenticate().catch((error) => {
  console.error('Authentication failed:', error.message);
  process.exit(1);
});
