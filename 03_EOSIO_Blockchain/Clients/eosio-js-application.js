const { JsonRpc, Api, RpcError, JsSignatureProvider } = require('eosjs');
const fetch = require('node-fetch');
const { TextEncoder, TextDecoder } = require('util');

const fs = require('fs');

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const rpc = new JsonRpc(config.httpEndpoint, { fetch });
const signatureProvider = new JsSignatureProvider(config.keyProvider);
const api = new Api({ rpc, signatureProvider, textEncoder: new TextEncoder(), textDecoder: new TextDecoder() });

// Your script logic goes here



const Blake2s = require('blake2s-js');

const privateKey = process.env.EOSIO_PRIVATE_KEY;
const contractAccount = 'YOUR_CONTRACT_ACCOUNT';
const authorizingAccount = 'YOUR_AUTHORIZING_ACCOUNT';
const rfidTag = 'YOUR_RFID_TAG';
const originalKey = 'YOUR_ORIGINAL_KEY'; // Replace with your actual original key

// Function to calculate BLAKE2s hash
function blake2s(data) {
   const hasher = new Blake2s();
   hasher.update(data);
   return hasher.digest('hex');
}


async function authenticate() {
   try {
      // Calculate BLAKE2s hash of the original key
      const hashedKey = blake2s(originalKey);

      // Send transaction to the EOSIO blockchain for authentication
      const result = await api.transact({
         actions: [{
            account: contractAccount,
            name: 'authenticate',
            authorization: [{
               actor: authorizingAccount,
               permission: 'active',
            }],
            data: {
               rfid_tag: rfidTag,
               key: hashedKey,
            },
         }],
      }, {
         blocksBehind: 3,
         expireSeconds: 30,
      });

      console.log('Authentication successful! Transaction ID:', result.transaction_id);
   } catch (error) {
      console.error('Authentication failed. Error:', error.message);
   }
}

authenticate();
