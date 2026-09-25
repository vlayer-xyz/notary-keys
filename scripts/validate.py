#!/usr/bin/env python3
"""Validate a notary key list.

    validate.py FILE [--base BASE_FILE] [--live]

Checks the file against schema.json and the invariants that the schema cannot
express (fingerprint derivation, window ordering, canonical formatting). With
--base, also enforces the change rules against the previous version of the
list. With --live, fetches GET /info from every notary of every open-window key
and compares the served key with the listed one.

Exits 0 when every check passes, 1 otherwise. Findings are printed one per line
as `ERROR: ...` or `WARN: ...`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema.json"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
CLOCK_SKEW = timedelta(hours=24)
LIVE_TIMEOUT_SECONDS = 15

errors: list[str] = []
warnings: list[str] = []


def error(message: str) -> None:
    errors.append(message)
    print(f"ERROR: {message}")


def warn(message: str) -> None:
    warnings.append(message)
    print(f"WARN: {message}")


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def load(path: Path) -> tuple[str, dict]:
    raw = path.read_text(encoding="utf-8")
    return raw, json.loads(raw)


def check_schema(document: dict) -> bool:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    problems = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    for problem in problems:
        location = "/".join(str(p) for p in problem.path) or "<root>"
        error(f"schema: {location}: {problem.message}")
    return not problems


def check_formatting(raw: str, document: dict) -> None:
    if raw != canonical_json(document):
        error(
            "file is not canonically formatted; regenerate with "
            "`python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); "
            "open(sys.argv[1],\"w\").write(json.dumps(d,indent=2,ensure_ascii=False)+\"\\n\")' FILE`"
        )


def check_updated_at_not_in_future(document: dict) -> None:
    updated_at = parse_timestamp(document["updatedAt"])
    if updated_at > datetime.now(timezone.utc) + CLOCK_SKEW:
        error(f"updatedAt {document['updatedAt']} is more than {CLOCK_SKEW} in the future")


def check_key(key: dict, index: int) -> None:
    label = f"keys[{index}] ({key['fingerprint'][:12]}…)"

    try:
        public_key = load_pem_public_key(key["publicKeyPem"].encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        error(f"{label}: publicKeyPem does not parse: {exc}")
        return
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        error(f"{label}: publicKeyPem is not an EC key")
        return

    if public_key.curve.name != key["curve"]:
        error(f"{label}: curve is {key['curve']} but publicKeyPem is {public_key.curve.name}")

    point = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    fingerprint = hashlib.sha256(point).hexdigest()
    if fingerprint != key["fingerprint"]:
        error(f"{label}: fingerprint is {key['fingerprint']} but sha256(compressed point) is {fingerprint}")

    pem_body = "".join(
        line for line in key["publicKeyPem"].splitlines() if not line.startswith("-----")
    )
    der = base64.b64decode(pem_body)
    if not der.endswith(point):
        error(
            f"{label}: publicKeyPem must encode the point in compressed form "
            "(as returned by the notary's GET /info), not uncompressed"
        )

    valid_from = parse_timestamp(key["validFrom"])
    if key["validUntil"] is not None:
        valid_until = parse_timestamp(key["validUntil"])
        if valid_until <= valid_from:
            error(f"{label}: validUntil {key['validUntil']} is not after validFrom {key['validFrom']}")


def check_unique_fingerprints(document: dict) -> None:
    seen: dict[str, int] = {}
    for index, key in enumerate(document["keys"]):
        if key["fingerprint"] in seen:
            error(f"keys[{index}]: duplicate fingerprint, first seen at keys[{seen[key['fingerprint']]}]")
        seen.setdefault(key["fingerprint"], index)


def check_against_base(document: dict, base: dict) -> None:
    """Change rules: entries are append-only, identity fields are immutable, an
    already-closed window may only be shortened, and any change to `keys` bumps
    `updatedAt`."""
    now = datetime.now(timezone.utc)
    head_by_fp = {k["fingerprint"]: k for k in document["keys"]}

    for old in base["keys"]:
        fp = old["fingerprint"]
        label = f"key {fp[:12]}…"
        new = head_by_fp.get(fp)
        if new is None:
            error(f"{label}: removed; entries are never deleted, set validUntil instead")
            continue
        for field in ("publicKeyPem", "curve", "validFrom"):
            if new[field] != old[field]:
                error(f"{label}: {field} changed; it is immutable once published")

        if old["validUntil"] is not None and new["validUntil"] != old["validUntil"]:
            old_until = parse_timestamp(old["validUntil"])
            if old_until <= now:
                if new["validUntil"] is None:
                    error(f"{label}: validUntil {old['validUntil']} has passed and cannot be reopened")
                elif parse_timestamp(new["validUntil"]) > old_until:
                    error(f"{label}: validUntil {old['validUntil']} has passed and can only be moved earlier")

    if document["keys"] != base["keys"]:
        if parse_timestamp(document["updatedAt"]) <= parse_timestamp(base["updatedAt"]):
            error(f"keys changed but updatedAt {document['updatedAt']} is not after {base['updatedAt']}")


def fetch_info_public_key(url: str) -> str:
    request = urllib.request.Request(f"{url.rstrip('/')}/info", headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=LIVE_TIMEOUT_SECONDS) as response:
        body = response.read().decode("utf-8")
    # notary-server emits the PEM with raw newlines inside the JSON string.
    return json.loads(body, strict=False)["publicKey"]


def check_live(document: dict) -> None:
    now = datetime.now(timezone.utc)
    for index, key in enumerate(document["keys"]):
        if key["validUntil"] is not None and parse_timestamp(key["validUntil"]) <= now:
            continue
        label = f"keys[{index}] ({key['fingerprint'][:12]}…)"
        for url in key["meta"]["notaryUrls"]:
            try:
                served = fetch_info_public_key(url)
            except Exception as exc:  # network errors are advisory
                warn(f"{label}: {url}/info unreachable: {exc}")
                continue
            if served == key["publicKeyPem"]:
                print(f"OK: {label}: {url}/info serves the listed key")
            else:
                error(f"{label}: {url}/info serves a different publicKey than publicKeyPem")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", type=Path)
    parser.add_argument("--base", type=Path, help="previous version of the list to enforce change rules against")
    parser.add_argument("--live", action="store_true", help="compare open-window keys with each notary's GET /info")
    args = parser.parse_args()

    raw, document = load(args.file)
    if not check_schema(document):
        return 1
    check_formatting(raw, document)
    check_updated_at_not_in_future(document)
    check_unique_fingerprints(document)
    for index, key in enumerate(document["keys"]):
        check_key(key, index)

    if args.base is not None:
        if args.base.exists():
            _, base = load(args.base)
            if check_schema(base):
                check_against_base(document, base)
            else:
                warn(f"base {args.base} does not validate; change rules skipped")
        else:
            print(f"OK: no base version at {args.base}; change rules skipped (new file)")

    if args.live:
        check_live(document)

    print(f"{args.file}: {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
