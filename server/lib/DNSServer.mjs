import debug from 'debug';
import dns2 from 'dns2';

import MongoDB from '../services/MongoDB.mjs';

import {
  PORT_DNS,
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

        if (question.type !== dns2.Packet.TYPE.A) {
          response.header.rcode = dns2.Packet.RCODE.NOTIMP;
          return send(response);
        }

        const { name } = question;
        const hostnameMatch = name.match(/^(?<hostname>[a-f0-9]{16})\.containarr\.me$/);
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