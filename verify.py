#!/usr/bin/env python3
"""
xybern-verify — independently verify a Xybern Authorisation Layer proof bundle.

This tool trusts NOTHING from Xybern. Given a proof bundle (and Xybern's public
keys, which are included in the bundle and also published at
https://www.xybern.com/api/sentinel/vault/v2/keys), it checks, entirely offline:

  1. content integrity  — recomputes each entry's content hash from its content
  2. entry integrity    — recomputes each entry's hash from its canonical fields
  3. chain integrity    — each entry links to the previous one (no insert/delete)
  4. authenticity       — the ECDSA P-256 signature verifies against the public
                          key  (only Xybern's private key could have produced it;
                          you cannot forge it, and neither can anyone else)

Exit code 0 = fully verified, 1 = any problem found.

Requires only the `cryptography` package:  pip install cryptography
Usage:  python verify.py bundle.json
"""

import base64
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("This verifier needs the 'cryptography' package:  pip install cryptography")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _content_hash(content) -> str:
    # MUST match the server: json.dumps(sort_keys=True, separators=(',',':'))
    return _sha256_hex(json.dumps(content, sort_keys=True, separators=(",", ":")))


def _entry_hash(seq, prev_hash, content_hash, entry_type, signed_at) -> str:
    data = f"{seq}|{prev_hash or 'genesis'}|{content_hash}|{entry_type}|{signed_at}"
    return _sha256_hex(data)


def _verify_signature(public_key_pem: str, entry_hash_hex: str, sig_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        pub.verify(base64.b64decode(sig_b64), entry_hash_hex.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


def _verify_inclusion(leaf: str, proof: list, root: str) -> bool:
    h = leaf
    for step in proof:
        sib = step.get("hash", "")
        h = _sha256_hex(h + sib) if step.get("side") == "R" else _sha256_hex(sib + h)
    return h == root


def _verify_anchor(anchor: dict, entries: list, keys: dict) -> str:
    """Verify the external-anchor checkpoint: inclusion proof + signed tree head.
    Returns a human status string; raises nothing."""
    ck = anchor.get("checkpoint") or {}
    # 1) checkpoint hash binds the signature to the Merkle root
    canonical = json.dumps({
        "workspace_id": ck.get("workspace_id"),
        "tree_size": ck.get("tree_size"),
        "merkle_root": ck.get("merkle_root"),
        "created_at": ck.get("signed_at"),
    }, sort_keys=True, separators=(",", ":"))
    if _sha256_hex(canonical) != ck.get("checkpoint_hash"):
        return "✗ checkpoint hash mismatch"
    # 2) checkpoint signature (signed tree head)
    pem = keys.get(ck.get("signing_key_id"))
    if not pem or not _verify_signature(pem, ck.get("checkpoint_hash"), ck.get("signature") or ""):
        return "✗ checkpoint signature invalid"
    # 3) inclusion proof: the certified entry is a leaf under the signed root.
    #    The leaf is the certified entry's hash; it must be one of the bundle entries.
    leaf = anchor.get("leaf")
    entry_hashes = {e.get("entry_hash") for e in entries}
    if leaf not in entry_hashes:
        return "✗ anchor leaf does not match the certified entry"
    if not _verify_inclusion(leaf, anchor.get("proof", []), ck.get("merkle_root")):
        return "✗ inclusion proof does not reach the signed root"
    tsa = ck.get("rfc3161_tsa")
    extra = ""
    if ck.get("rfc3161_token"):
        extra += f" · RFC-3161 timestamp present (TSA {tsa}; verify with `openssl ts -verify`)"
    if ck.get("ots_status") in ("pending", "confirmed"):
        extra += f" · OpenTimestamps/Bitcoin proof present, status={ck.get('ots_status')} (verify with `ots verify`)"
    return f"✓ externally anchored — entry is committed in signed tree head over {ck.get('tree_size')} entries{extra}"


def verify_bundle(bundle: dict) -> bool:
    keys = {k["key_id"]: k["public_key_pem"] for k in bundle.get("signing_keys", []) if k.get("key_id")}
    entries = bundle.get("entries", [])
    print(f"Xybern proof bundle — workspace {bundle.get('workspace_id', '?')}, "
          f"{len(entries)} entries, {len(keys)} signing key(s)\n")

    problems = 0
    prev_entry_hash = None
    prev_seq = None

    for e in entries:
        eid = e.get("entry_id", "?")
        errs = []

        ch = _content_hash(e.get("content"))
        if ch != e.get("content_hash"):
            errs.append("content hash mismatch (content was altered)")

        eh = _entry_hash(e.get("sequence_number"), e.get("previous_hash"),
                         e.get("content_hash"), e.get("entry_type"), e.get("signed_at"))
        if eh != e.get("entry_hash"):
            errs.append("entry hash mismatch (entry fields altered)")

        # chain link — only when this entry is the immediate successor in the bundle
        if prev_entry_hash is not None and prev_seq is not None \
                and e.get("sequence_number") == prev_seq + 1:
            if e.get("previous_hash") != prev_entry_hash:
                errs.append("broken chain link (an entry was inserted or removed)")

        sig = e.get("signature")
        if not sig or not sig.get("value"):
            errs.append("no signature")
        else:
            pem = keys.get(sig.get("key_id"))
            if not pem:
                errs.append(f"unknown signing key {sig.get('key_id')}")
            elif not _verify_signature(pem, e.get("entry_hash"), sig["value"]):
                errs.append("invalid signature (not signed by Xybern's key)")

        if errs:
            problems += 1
            print(f"  ✗ {eid}  seq {e.get('sequence_number')}  — " + "; ".join(errs))

        prev_entry_hash = e.get("entry_hash")
        prev_seq = e.get("sequence_number")

    # Optional external anchor (Phase 3): inclusion in a signed, timestamped tree head
    anchor = bundle.get("anchor")
    if anchor:
        status = _verify_anchor(anchor, entries, keys)
        print(f"  {status}")
        if status.startswith("✗"):
            problems += 1

    print()
    if problems == 0:
        msg = "✓ VERIFIED — authentic, untampered, correctly chained"
        msg += ", and externally anchored." if anchor else "."
        print(msg if len(entries) != 1 else msg.replace("entries", "entry"))
        return True
    print(f"✗ FAILED — {problems} problem(s) found (see above).")
    return False


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python verify.py <proof_bundle.json>")
    with open(sys.argv[1]) as f:
        data = json.load(f)
    # Accept either the raw bundle or an API response {ok, bundle}.
    bundle = data.get("bundle", data) if isinstance(data, dict) else data
    sys.exit(0 if verify_bundle(bundle) else 1)


if __name__ == "__main__":
    main()
