// Usage: node tools/generate-keypair.mjs

import crypto from 'node:crypto';

const {
  publicKey,
  privateKey,
} = crypto.generateKeyPairSync('ed25519');

console.log(`Public Key: ${publicKey.export({
  type: 'spki',
  format: 'der',
}).toString('base64url')}`);

console.log(`Private Key: ${privateKey.export({
  type: 'pkcs8',
  format: 'der',
}).toString('base64url')}`);

const fingerprint = crypto.createHash('sha256')
  .update(publicKey.export({
    type: 'spki',
    format: 'der',
  }))
  .digest('hex')
  .slice(0, 16);

console.log(`Fingerprint: ${fingerprint}`);
console.log(`Hostname: ${fingerprint}.containarr.me`);