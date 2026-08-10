import net from 'node:net';

import debug from 'debug';
import express from 'express';

import Util from './Util.mjs';

import MongoDB from '../services/MongoDB.mjs';

import {
  PORT_HTTP,
} from '../config.mjs';

export default class HTTPServer {

  debug = debug('HTTPServer');

  constructor() {
    this.app = express();
    this.app.use(express.json());
    this.app.set('trust proxy', true);
    this.app.listen(PORT_HTTP, err => {
      if (err) {
        this.debug(err);
        return process.exit(1);
      }

      this.debug(`Listening on 0.0.0.0:${PORT_HTTP}`);
    });

    this.app.get('/', (req, res) => {
      res.redirect('https://containarr.com');
    });

    this.app.put('/api/v1/record', async (req, res) => {
      if (typeof req.body !== 'object') {
        return res.status(401).json({ error: 'Missing Body' });
      }

      const {
        publicKey,
        signature,
        timestamp,
        requestId,
      } = req.body;

      if (typeof publicKey !== 'string') {
        return res.status(401).json({ error: 'Missing Public Key' });
      }

      if (typeof signature !== 'string') {
        return res.status(401).json({ error: 'Missing Signature' });
      }

      if (typeof timestamp !== 'number') {
        return res.status(401).json({ error: 'Missing Timestamp' });
      }

      const now = Date.now();
      if (Math.abs(now - timestamp) > 1000 * 60 * 5) {
        return res.status(401).json({ error: 'Invalid Timestamp' });
      }

      const {
        isValid,
        fingerprint,
      } = Util.validateSignature({
        timestamp,
        publicKey: Buffer.from(publicKey, 'base64url'),
        signature: Buffer.from(signature, 'base64url'),
      });

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid Signature' });
      }

      const modelDNSRecord = await MongoDB.getModelDNSRecord();
      await modelDNSRecord.findOneAndUpdate({
        hostname: fingerprint,
      }, {
        hostname: fingerprint,
        ipv4: net.isIPv4(req.ip)
          ? req.ip
          : null,
        ipv6: net.isIPv6(req.ip)
          ? req.ip
          : null,
        updatedAt: new Date(),
      }, {
        upsert: true,
      });

      res.status(200).json({
        ok: true,
      });
    });
  }
}