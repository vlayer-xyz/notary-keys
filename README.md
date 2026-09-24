# Vouch notary keys

The authoritative list of signing keys used by [Vouch](https://getvouch.io) notaries.

Every web proof carries the notary's public key inside the presentation, so TLSN
verification alone only tells you that *some* key signed the attestation. To know
that the key belongs to a Vouch notary, compare it against this list.

| Environment | URL |
| --- | --- |
| Production | `https://keys.vlayer.xyz/notary-keys.json` |

Changes are made by pull request to this repository and served from `main` via
GitHub Pages. The commit history is the audit trail; an immutable snapshot of any
version is available at `https://raw.githubusercontent.com/vlayer-xyz/notary-keys/<commit>/notary-keys.json`.

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
| `keys[].fingerprint` | Primary identifier of the key. Equals `notaryKeyFingerprint` returned by the Vouch verify API. |
| `keys[].publicKeyPem` | The key as a compressed-point SubjectPublicKeyInfo PEM, byte-identical to the `publicKey` field of the notary's `GET /info`. |
| `keys[].curve` | `secp256k1` or `secp256r1`. |
| `keys[].validFrom` | Start of the window in which the key signed proofs (inclusive). |
| `keys[].validUntil` | End of the window (exclusive), or `null` while the key is in use. Set when the key is rotated out. |
| `keys[].meta` | Informational only. Verifiers must not base any decision on it. `notaryUrls` lists the notaries signing with the key. |

Entries are never removed: a key that has been rotated out stays listed with its
`validUntil` set, so proofs it signed remain verifiable. Several keys may have an
open window at the same time. Unknown fields must be ignored.

## Verifier rule

Accept a proof if and only if:

1. its notary key fingerprint appears in `keys`, and
2. `validFrom <= tlsTimestamp < validUntil` for that entry (`validUntil: null` means no upper bound),

where `tlsTimestamp` is the TLS session time recorded in the attestation (returned
as `tlsTimestamp` by the Vouch verify API). This is what keeps proofs signed by a
since-rotated key verifiable. Verifiers that cannot evaluate timestamps may
instead accept any key whose `validUntil` is `null` or in the future.

Do not use the `notaryUrl` carried inside a presentation as a trust input; only the
key matters.

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
you have been unable to refresh as stale. Rotations are announced ahead of time and
published with an overlap window, so a copy that is a few hours old is safe; a copy
that is weeks old is not.

## Making changes

- **Add a key** (rotation or a new notary): append an entry with `validFrom` set to
  the planned cutover and `validUntil: null`. Verifiers accept it from `validFrom`
  onward without a second edit.
- **Rotate a key out**: set its `validUntil` to the moment the last notary stopped
  signing with it. Do not remove the entry.
- **Compromised key**: set `validUntil` to the earliest known or suspected
  compromise time, in a single emergency pull request merged before the notary is
  rotated, and record the incident under `meta`.

Every change bumps `updatedAt`.
