// Usage:
// node tools/update-record.mjs --publicKey <publicKey> --privateKey <privateKey>

import crypto from 'node:crypto';
import util from 'node:util';

const { values } = util.parseArgs({
  options: {
    'public-key': {
      type: 'string',
    },
    'private-key': {
      type: 'string',
    },
    'api-url': {
      type: 'string',
      default: 'https://containarr.me/api/v1/record',
    },
  },
});

if (!values['public-key']) {
  throw new Error('Missing Public Key');
}

if (!values['private-key']) {
  throw new Error('Missing Private Key');
}

const publicKey = crypto.createPublicKey({
  key: Buffer.from(values['public-key'], 'base64url'),
  format: 'der',
  type: 'spki',
});

const privateKey = crypto.createPrivateKey({
  key: Buffer.from(values['private-key'], 'base64url'),
  format: 'der',
  type: 'pkcs8',
});

const timestamp = Date.now();
console.log(`Timestamp: ${timestamp}`);

const signature = crypto.sign(null, Buffer.from(`${timestamp}`), {
  key: privateKey,
});

console.log(`Signature: ${signature.toString('base64url')}`);

const isValid = crypto.verify(null, Buffer.from(`${timestamp}`), {
  key: publicKey,
  format: 'der',
  type: 'spki',
}, signature);
console.log(`Is Valid: ${isValid}`);

const fingerprint = crypto.createHash('sha256')
  .update(publicKey.export({
    type: 'spki',
    format: 'der',
  }))
  .digest('hex')
  .slice(0, 16);

console.log(`Fingerprint: ${fingerprint}`);
console.log(`Hostname: ${fingerprint}.containarr.me`);

const apiUrl = values['api-url'];
console.log(`API URL: ${apiUrl}`);

const result = await fetch(apiUrl, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    publicKey: values['public-key'],
    signature: signature.toString('base64url'),
    timestamp,
  }),
});
console.log(`API Response: ${result.status} ${result.statusText}`);