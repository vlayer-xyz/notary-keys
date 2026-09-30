// Frozen test fixtures, independent of the committed list so that editing the list never breaks
// the validator's own tests.

export const SECP256K1 = {
  fingerprint: "a7e62d7f17aa7a22c26bdb93b7ce9400e826ffb2c6f54e54d2ded015677499af",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDYwEAYHKoZIzj0CAQYFK4EEAAoDIgAC1Mu6mQsMLrHdRbKcfSYHUpnx6jkxfzUU\nDm73HnA77ac=\n-----END PUBLIC KEY-----\n",
  curve: "secp256k1",
};
// SECP256K1's point in uncompressed (04‖x‖y) SubjectPublicKeyInfo form.
export const UNCOMPRESSED_PEM =
  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1Mu6mQsMLrHdRbKcfSYHUpnx6jkxfzUU\nDm73HnA77acXaF7sNQHVOPqtLYC1ldmYzWLpT/Pvtnja/1YTblMSMA==\n-----END PUBLIC KEY-----\n";

export const SECP256K1_OTHER = {
  fingerprint: "6cff271c5511747721a2fbe2f1e7f5a9520241bf95d1afc72b34a70e144da0d7",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACZt/aZXbuq7OIL+cOSRqyG9jJTGtxPsPf\nFatke4wKM50=\n-----END PUBLIC KEY-----\n",
  curve: "secp256k1",
};

export const SECP256R1 = {
  fingerprint: "4881d57e2983140922e2e6ff82a8debde60efe9dfe602b7cb790864fed74d45b",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADu2+daX2o5/bkgvgRBPyUupnPSeQx\nH7QkhXnJ7SE6fzw=\n-----END PUBLIC KEY-----\n",
  curve: "secp256r1",
};

export const ED25519_PEM =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJg74j33enoHb3BSx6aNgl7nTQzDus+JoHDxI9/gzjHs=\n-----END PUBLIC KEY-----\n";
export const P384_PEM =
  "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERAVYS0YoyeTEGAW04+Pawg8ogeI0+JqI\n98crnO8GUDpldZwRdVRuwJI+L2SwOuRxKhiBWe9DHhNU6+GPgNoc4Icaq6DTzbfh\ng7D437He82CWAchvPoidvGEvDXY1Xn4E\n-----END PUBLIC KEY-----\n";
// secp256k1 SubjectPublicKeyInfo whose point is the single byte 00: the point at infinity.
export const INFINITY_PEM = "-----BEGIN PUBLIC KEY-----\nMBYwEAYHKoZIzj0CAQYFK4EEAAoDAgAA\n-----END PUBLIC KEY-----\n";

/** A valid list with one key whose window opened in 2024 and has no end. */
export const FIXTURE = {
  schemaVersion: 1,
  updatedAt: "2026-09-01T00:00:00Z",
  fingerprintAlgorithm: "sha256 over compressed SEC1 public key, lowercase hex",
  keys: [
    {
      ...SECP256K1,
      validFrom: "2024-11-28T00:00:00Z",
      validUntil: null,
      meta: { notaryUrls: ["https://notary.example.com", "https://legacy.example.com"] },
    },
  ],
};

export const serialize = (doc) => `${JSON.stringify(doc, null, 2)}\n`;
