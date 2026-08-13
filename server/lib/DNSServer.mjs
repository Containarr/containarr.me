import debug from 'debug';
import dns2 from 'dns2';

import MongoDB from '../services/MongoDB.mjs';

import {
  PORT_DNS,
  HOST_IP,
} from '../config.mjs';

export default class DNSServer {

  debug = debug('DNSServer');

  constructor() {
    this.server = dns2.createServer({
      udp: true,
      handle: (request, send, rinfo) => {
        if (request.errors.length) {
          const response = dns2.Packet.createResponseFromRequest(request);
          response.header.rcode = dns2.Packet.RCODE.FORMERR;
          return send(response);
        }

        const response = dns2.Packet.createResponseFromRequest(request);
        const [question] = request.questions;
        if (!question) {
          response.header.rcode = dns2.Packet.RCODE.FORMERR;
          return send(response);
        }

        // This server is authoritative for containarr.me
        response.header.aa = 1;

        // Allow Let's Encrypt to issue certificates for containarr.me and its subdomains
        if (
          question.type === dns2.Packet.TYPE.CAA
          && (
            question.name === 'containarr.me'
            || question.name.endsWith('.containarr.me')
          )
        ) {
          response.answers.push({
            name: question.name,
            type: dns2.Packet.TYPE.CAA,
            class: dns2.Packet.CLASS.IN,
            ttl: 60,
            flags: 0,
            tag: 'issue',
            value: 'letsencrypt.org',
          });

          return send(response);
        }

        // Answer A containarr.me
        if (question.type === dns2.Packet.TYPE.A && question.name === 'containarr.me') {
          response.answers.push({
            name: question.name,
            type: dns2.Packet.TYPE.A,
            class: dns2.Packet.CLASS.IN,
            ttl: 60,
            address: HOST_IP,
          });

          return send(response);
        }

        // Answer NS containarr.me
        if (question.type === dns2.Packet.TYPE.NS && question.name === 'containarr.me') {
          response.answers.push(
            {
              name: question.name,
              type: dns2.Packet.TYPE.NS,
              class: dns2.Packet.CLASS.IN,
              ttl: 60,
              ns: 'ns1.containarr.me',
            },
            {
              name: question.name,
              type: dns2.Packet.TYPE.NS,
              class: dns2.Packet.CLASS.IN,
              ttl: 60,
              ns: 'ns2.containarr.me',
            }
          );

          return send(response);
        }

        // Answer A ns1.containarr.me
        if (question.type === dns2.Packet.TYPE.A && question.name === 'ns1.containarr.me') {
          response.answers.push({
            name: question.name,
            type: dns2.Packet.TYPE.A,
            class: dns2.Packet.CLASS.IN,
            ttl: 60,
            address: HOST_IP,
          });

          return send(response);
        }

        // Answer A ns2.containarr.me
        if (question.type === dns2.Packet.TYPE.A && question.name === 'ns2.containarr.me') {
          response.answers.push({
            name: question.name,
            type: dns2.Packet.TYPE.A,
            class: dns2.Packet.CLASS.IN,
            ttl: 60,
            address: HOST_IP,
          });

          return send(response);
        }

        // Answer SOA containarr.me
        if (question.type === dns2.Packet.TYPE.SOA && question.name === 'containarr.me') {
          response.answers.push({
            name: question.name,
            type: dns2.Packet.TYPE.SOA,
            class: dns2.Packet.CLASS.IN,
            ttl: 60,

            primary: 'ns1.containarr.me',
            admin: 'admin.containarr.me',

            serial: 2026081001,

            refresh: 3600,
            retry: 600,
            expiration: 604800,
            minimum: 60,
          });

          return send(response);
        }

        // Answer A and AAAA questions for <hostname>.containarr.me
        if (question.type !== dns2.Packet.TYPE.A) {
          response.header.rcode = dns2.Packet.RCODE.NOTIMP;
          return send(response);
        }

        const name = question.name.toLowerCase();
        const hostnameMatch = name.match(/^(?:[^.]+\.)?(?<hostname>[a-f0-9]{16})\.containarr\.me$/);
        if (!hostnameMatch) {
          response.header.rcode = dns2.Packet.RCODE.NXDOMAIN;
          return send(response);
        }

        const { hostname } = hostnameMatch.groups;

        Promise.resolve()
          .then(async () => {
            const DNSRecord = await MongoDB.getModelDNSRecord();
            const record = await DNSRecord.findOne({ hostname });
            if (!record) {
              response.header.rcode = dns2.Packet.RCODE.NXDOMAIN;
              return send(response);
            }

            if (record.ipv4) {
              response.answers.push({
                name,
                type: dns2.Packet.TYPE.A,
                class: dns2.Packet.CLASS.IN,
                ttl: 60,
                address: record.ipv4,
              });
            }

            if (record.ipv6) {
              response.answers.push({
                name,
                type: dns2.Packet.TYPE.AAAA,
                class: dns2.Packet.CLASS.IN,
                ttl: 60,
                address: record.ipv6,
              });
            }

            if (response.answers.length === 0) {
              response.header.rcode = dns2.Packet.RCODE.NXDOMAIN;
            }

            return send(response);
          })
          .catch(err => {
            response.header.rcode = dns2.Packet.RCODE.SERVFAIL;
            return send(response);
          });
      },
    });

    this.server.on('requestError', err => {
      this.debug(`Request Error: ${err.message}`);
    });

    this.server.listen({
      udp: {
        port: PORT_DNS,
      },
    });

    this.server.on('listening', () => {
      const { udp } = this.server.addresses();
      this.debug(`Listening on ${udp.address}:${udp.port}`);
    });

    this.server.on('close', () => {
      this.debug('Server closed');
      process.exit(1);
    });
  }

}
