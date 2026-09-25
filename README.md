# vlayer notary keys

The authoritative list of signing keys used by [vlayer](https://vlayer.xyz/) notaries.

Every web proof carries the notary's public key inside the presentation, so TLSN
verification alone only tells you that *some* key signed the attestation. To know
that the key belongs to a vlayer notary, compare it against this list.

| Environment | URL |
| --- | --- |
| Production | `https://keys.vlayer.xyz/notary-keys.production.json` |
| JSON Schema | `https://keys.vlayer.xyz/schema.json` |

Changes are made by pull request to this repository and served from `main` via
GitHub Pages. The commit history is the audit trail; an immutable snapshot of any
version is available at `https://raw.githubusercontent.com/vlayer-xyz/notary-keys/<commit>/notary-keys.production.json`.

## Format

```json
{
  "schemaVersion": 1,
  "updatedAt": "2026-09-24T00:00:00Z",
  "fingerprintAlgorithm": "sha256 over compressed SEC1 public key, lowercase hex",
  "keys": [
    {
      "fingerprint": "a7e62d7f17aa7a22c26bdb93b7ce9400e826ffb2c6f54e54d2ded015677499af",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "curve": "secp256k1",
      "validFrom": "2024-11-28T00:00:00Z",
      "validUntil": null,
      "meta": {
        "notaryUrls": ["https://notary.production.vlayer.xyz"]
      }
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Bumped only for changes that affect the verifier rule below. |
| `updatedAt` | When this version of the list was published. |
| `fingerprintAlgorithm` | How `fingerprint` is derived from the key; see [Fingerprints](#fingerprints). |
| `keys[].fingerprint` | Primary identifier of the key. Equals `notaryKeyFingerprint` returned by the [vlayer verify API](https://platform.vlayer.xyz/server-side/rest-api/verify). |
| `keys[].publicKeyPem` | The key as a compressed-point SubjectPublicKeyInfo PEM, byte-identical to the `publicKey` field of the notary's `GET /info`. |
| `keys[].curve` | `secp256k1` or `secp256r1`. |
| `keys[].validFrom` | Start of the window in which the key signed proofs (inclusive). |
| `keys[].validUntil` | *Mutable*. End of the window (exclusive), or `null` when the key doesn't have end of validity set yet. Set when the key is rotated out or is going to be rotated out. |
| `keys[].meta` | Informational only. Verifiers must not base any decision on it. `notaryUrls` lists the notaries signing with the key. |

Entries are never removed: a key that has been rotated out stays listed with its
`validUntil` set, so proofs it signed remain verifiable. Several keys may have an
open window at the same time. Unknown fields must be ignored.

## Verifier rule

Accept a proof if and only if:

1. its notary key fingerprint appears in `keys`, and
2. `validFrom <= tlsTimestamp < validUntil` for that entry (`validUntil: null` means no upper bound),

where `tlsTimestamp` is the TLS session time recorded in the attestation (returned
as `tlsTimestamp` by the [vlayer verify API](https://platform.vlayer.xyz/server-side/rest-api/verify)). This is what keeps proofs signed by a
since-rotated key verifiable.

## Fingerprints

A fingerprint is the SHA-256 digest of the key's compressed SEC1 point (33 bytes,
`02`/`03` prefix), encoded as 64 lowercase hex characters. To recompute it from a
PEM:

```sh
openssl ec -pubin -in notary.pub -conv_form compressed -outform DER 2>/dev/null \
  | tail -c 33 | shasum -a 256 | cut -d' ' -f1
```

To cross-check an entry against a live notary:

```sh
curl -s https://notary.production.vlayer.xyz/info \
  | jq -r .publicKey \
  | openssl ec -pubin -conv_form compressed -outform DER 2>/dev/null \
  | tail -c 33 | shasum -a 256 | cut -d' ' -f1
```

The output must match the entry's `fingerprint`, and the `publicKey` string must
match `publicKeyPem` byte for byte.

## Caching

The file is served with `Cache-Control: max-age=600` and an `ETag`. Poll it on a
schedule, send `If-None-Match` to make unchanged fetches cheap, and treat a copy
you have been unable to refresh as stale.

## Making changes

- **Add a key** (rotation or a new notary): append an entry with `validFrom` set to
  the planned cutover and `validUntil: null`. Verifiers accept it from `validFrom`
  onward without a second edit.
- **Rotate a key out**: set its `validUntil` to the moment the last notary will stop
  signing with it, before it actually happens. Do not remove the entry.

Every change bumps `updatedAt`.

CI (`.github/workflows/validate.yml`, `scripts/validate.ts`) enforces on every pull
request: the file matches [`schema.json`](schema.json) and is canonically formatted
(2-space indent, trailing newline); every timestamp is a real UTC instant; each
`fingerprint` equals the SHA-256 of the compressed point recomputed from
`publicKeyPem`, `curve` matches the key, and the PEM is in compressed form;
fingerprints are unique; `validUntil` is after `validFrom`; no entry is removed and
`publicKeyPem`, `curve`, `validFrom` never change; a `validUntil` that has already
passed can only be moved earlier; `updatedAt` is bumped whenever `keys` changes. A
separate advisory job fetches `GET /info` from every notary of every open-window key
and compares the served key with the listed one. To run locally (Node 24+, pnpm):

```sh
pnpm install
node scripts/validate.ts notary-keys.production.json --base <(git show main:notary-keys.production.json) --live
```
