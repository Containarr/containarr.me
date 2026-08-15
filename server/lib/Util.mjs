import crypto from 'node:crypto';

export default class Util {

  static validateSignature({
    data,
    publicKey,
    signature,
  }) {
    publicKey = crypto.createPublicKey({
      key: Buffer.from(publicKey, 'base64url'),
      format: 'der',
      type: 'spki',
    });

    const isValid = crypto.verify(null, Buffer.from(data), {
      key: publicKey,
      format: 'der',
      type: 'spki',
    }, Buffer.from(signature, 'base64url'));

    const fingerprint = crypto.createHash('sha256')
      .update(publicKey.export({
        type: 'spki',
        format: 'der',
      }))
      .digest('hex')
      .slice(0, 16);

    return {
      isValid,
      fingerprint,
    };
  }

}
