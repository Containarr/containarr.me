# containarr.me

This service is a Dynamic DNS service without accounts. It makes hostnames like `7b4988825f1bddb7.containarr.me` point to your IP address. The intent is for you to create a `CNAME` record from e.g. `*.homelab.johndoe.com` to this host.

The service itself is a HTTP server to receive IP address updates, and a DNS server to resolve queries to your domain. The DNS records are stored in MongoDB.

The service has no accounts on purpose, but authenticates with a public/private key generated and stored on the customer's machine. The hostname (`foo.containarr.me`) is the key's fingerprint first 16 characters.

> The service is currently hosted in 🇩🇪 Germany on Hetzner, and the database is managed by MongoDB Atlas, running in 🇩🇪 Frankfurt on Amazon Web Services.

## Running Locally

```bash
$ docker compose up
```