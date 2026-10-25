# HMN · Verify

The public page that checks an HMN (Human Made Notary) certificate of human creation. Everything is verified in the visitor's browser: the certificate's ID and Ed25519 signature, Merkle inclusion of its trail in HMN's public append-only log (RFC 6962), the signed log head, and the daily Bitcoin anchor (OpenTimestamps).

Open with `?c=<certificate ID>`, for example `?c=7F3K-2Q9M`.
