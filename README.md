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
| `keys[].validFrom` | Start of the window in which the key signed proofs (inclusive). Immutable once it has passed; while it is still in the future it may be corrected. If a planned cutover slips, the entry may keep the earlier `validFrom`, which is harmless because no proof exists from before the key was actually used. |
| `keys[].validUntil` | *Mutable*. End of the window (exclusive), or `null` when the key doesn't have end of validity set yet. Set when the key is rotated out or is going to be rotated out. |
| `keys[].meta` | Informational only. Verifiers must not base any decision on it. `notaryUrls` lists the origins of the notaries signing with the key; `GET <origin>/info` serves the key. |

Entries are never removed: a key that has been rotated out stays listed with its
`validUntil` set, so proofs it signed remain verifiable. Several keys may have an
open window at the same time.

Verifiers must ignore fields they don't recognise, at any level. The published
`schema.json` describes only the fields above and accepts others; new fields never
change the meaning of existing ones without a `schemaVersion` bump.

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

Every change sets `updatedAt` to the current UTC time (`date -u +%FT%TZ`); a change
that keeps the previous `updatedAt`, or sets one more than 7 days old, is rejected.

## Validation

Every pull request runs the [validator](scripts/validate-notary-keys.js) against the
version of each list on the base branch. It fails on:

- a list that does not match `schema.json`, has a field outside those described
  (except inside `meta`), lacks `meta.notaryUrls`, or is not formatted as
  `JSON.stringify(doc, null, 2)` with a trailing newline;
- a timestamp that is not a real UTC instant, an `updatedAt` more than 1 h in the
  future, a `validUntil` not after `validFrom`, or two entries with the same `fingerprint`;
- a `fingerprint`, `curve` or `publicKeyPem` that does not match the key itself
  (`publicKeyPem` must be the compressed-point form the notary serves, byte for byte);
- a removed or renamed list, a removed entry, a change to `publicKeyPem` or `curve`, or
  a change to a `validFrom` that has already passed;
- a `validUntil` that had already passed being moved later or back to `null`;
- a new or changed `validFrom`, or any change to a `validUntil`, more than 7 days in the
  past — the list cannot be backdated, and a retroactive close cannot be undone. A key
  compromise that needs a deeper cut changes the grace period in
  [`scripts/rules.js`](scripts/rules.js) in the same pull request, where reviewers see it;
- `updatedAt` moving backwards, or, when anything else changed, not moving or being
  more than 7 days old.

The "already passed", "in the past" and "old" rules are evaluated at the time the check
runs. A pull request that has been open for more than a few days should have `updatedAt`
refreshed and be re-run ("Re-run all jobs" on the check) right before merging.

Additionally, for every key whose window is currently open, the notaries in
`meta.notaryUrls` are queried and a `publicKey` that differs from `publicKeyPem` is
reported as a warning. This never fails the check: a difference is expected while a
rotation is in progress.

The check catches mistakes. It is not a defence against a malicious pull request,
which could change the rules in the same diff: review changes under `scripts/`,
`schema.json`, `.github/`, `package.json`, `pnpm-lock.yaml` and the GitHub Pages
files (`CNAME`, `index.html`, `.nojekyll`) with the same care as the key list itself.

Locally, with the Node version from `.nvmrc` and the pnpm version from `package.json`
(`nvm use && corepack enable`):

```sh
pnpm install
pnpm test
pnpm validate --base origin/main
```
