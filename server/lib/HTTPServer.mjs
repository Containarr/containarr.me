import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';

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

    this.app.get('/health', (req, res) => {
      res.status(200).send('OK');
    });

    this.app.put('/api/v1/record', async (req, res) => {
      // Validate the request
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

      // Validate the signature
      let validation;
      try {
        validation = Util.validateSignature({
          data: `${timestamp}`,
          publicKey,
          signature,
        });
      } catch {
        return res.status(401).json({ error: 'Invalid Public Key' });
      }

      if (!validation.isValid) {
        return res.status(401).json({ error: 'Invalid Signature' });
      }

      // Store the installation's current public IP address
      const modelDNSRecord = await MongoDB.getModelDNSRecord();
      await modelDNSRecord.findOneAndUpdate({
        hostname: validation.fingerprint,
      }, {
        hostname: validation.fingerprint,
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

    this.app.post('/api/v1/domain/check', async (req, res) => {
      // Validate the request
      if (typeof req.body !== 'object') {
        return res.status(401).json({ error: 'Missing Body' });
      }

      const {
        domain,
        publicKey,
        signature,
        timestamp,
      } = req.body;

      if (
        typeof domain !== 'string'
        || domain.length > 253
        || domain.split('.').length < 2
        || domain.split('.').some(label => (
          label.length < 1
          || label.length > 63
          || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
        ))
      ) {
        return res.status(400).json({ error: 'Invalid Domain' });
      }
      if (typeof publicKey !== 'string') {
        return res.status(401).json({ error: 'Missing Public Key' });
      }
      if (typeof signature !== 'string') {
        return res.status(401).json({ error: 'Missing Signature' });
      }
      if (typeof timestamp !== 'number') {
        return res.status(401).json({ error: 'Missing Timestamp' });
      }
      if (Math.abs(Date.now() - timestamp) > 1000 * 60 * 5) {
        return res.status(401).json({ error: 'Invalid Timestamp' });
      }

      // Validate the signature
      let validation;
      try {
        validation = Util.validateSignature({
          data: `${timestamp}:${domain}`,
          publicKey,
          signature,
        });
      } catch {
        return res.status(401).json({ error: 'Invalid Public Key' });
      }

      if (!validation.isValid) {
        return res.status(401).json({ error: 'Invalid Signature' });
      }

      // Derive the expected CNAME target from the installation's public key
      const hostname = `containarr-check.${domain}`;
      const expectedTarget = `${validation.fingerprint}.containarr.me`;

      // Validate the CNAME
      let dnsResult;
      try {
        const targets = (await new Promise((resolve, reject) => {
          dns.resolveCname(hostname, (error, addresses) => {
            if (error) return reject(error);
            resolve(addresses);
          });
        })).map(target => target.toLowerCase().replace(/\.$/, ''));
        dnsResult = {
          configured: targets.includes(expectedTarget),
          target: targets[0] ?? null,
          error: targets.includes(expectedTarget)
            ? null
            : `Expected ${expectedTarget}.`,
        };
      } catch (error) {
        dnsResult = {
          configured: false,
          target: null,
          error: error.message,
        };
      }

      // Check whether the installation is reachable over HTTP and HTTPS
      const [httpResult, httpsResult] = await Promise.all([
        new Promise(resolve => {
          const request = http.request({
            hostname,
            method: 'GET',
            path: '/',
          }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => {
              body += chunk;
            });
            response.on('end', () => {
              const reachable = response.statusCode >= 200
                && response.statusCode < 300
                && body.trim() === expectedTarget;
              resolve({
                reachable,
                statusCode: response.statusCode ?? null,
                error: reachable
                  ? null
                  : /^[a-f0-9]{16}\.containarr\.me$/.test(body.trim())
                    ? `Reached ${body.trim()}, not ${expectedTarget}.`
                    : 'Response is not this Containarr installation.',
              });
            });
          });

          request.setTimeout(5000, () => request.destroy(new Error('Timed out.')));
          request.once('error', error => resolve({
            reachable: false,
            statusCode: null,
            error: error.message,
          }));
          request.end();
        }),
        new Promise(resolve => {
          const request = https.request({
            hostname,
            method: 'GET',
            path: '/',
            servername: hostname,
            rejectUnauthorized: false,
          }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => {
              body += chunk;
            });
            response.on('end', () => {
              const reachable = response.statusCode >= 200
                && response.statusCode < 300
                && body.trim() === expectedTarget;
              resolve({
                reachable,
                statusCode: response.statusCode ?? null,
                error: reachable
                  ? null
                  : /^[a-f0-9]{16}\.containarr\.me$/.test(body.trim())
                    ? `Reached ${body.trim()}, not ${expectedTarget}.`
                    : 'Response is not this Containarr installation.',
              });
            });
          });

          request.setTimeout(5000, () => request.destroy(new Error('Timed out.')));
          request.once('error', error => resolve({
            reachable: false,
            statusCode: null,
            error: error.message,
          }));
          request.end();
        }),
      ]);

      res.status(200).json({
        hostname,
        expectedTarget,
        dns: dnsResult,
        http: httpResult,
        https: httpsResult,
      });
    });
  }
}
