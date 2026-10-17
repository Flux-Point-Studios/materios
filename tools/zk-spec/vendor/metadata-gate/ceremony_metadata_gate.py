#!/usr/bin/env python3
"""Pre-flight metadata-diff + bound-vs-live gate for a forkless runtime upgrade
(mainnet-resilience #494).

The existing ceremony checks constants/calls in the POST-flight step — i.e. AFTER
the upgrade is already live. That is exactly how spec-214/217 shipped a silent
`MaxCommitteeSize` regression: the bad WASM was deployed, then discovered. This
gate runs BEFORE `authorize_upgrade`: it extracts the NEW WASM's metadata, diffs
it against the LIVE runtime, and refuses to proceed unless the diff EXACTLY equals
a hand-declared expectation manifest (the intended adds/removes) AND the drift
canary constants — read FROM the new WASM, not a hardcoded source value — match,
AND the new WASM hashes to the audited artifact's code_hash.

Type fingerprints are STRUCTURAL (recurse composite fields + variant variants +
containers), so a retype hidden inside a struct or bounded collection, an
alias-hidden call-arg wire change, or a same-typed arg reorder is caught — not
just a top-level type-string change. Added-pallet internals, per-pallet events and
errors, and the extrinsic's signed extensions are all diffed too.

FRAME metadata does NOT encode dispatch ORIGINS or handler LOGIC. A call that
flips ensure_root -> ensure_signed, a second privileged origin, or a swapped call
body has identical metadata and passes. This gate is NECESSARY-NOT-SUFFICIENT: run
it alongside a source/commit diff of the exact tree (audit every ensure_* site) and
the code_hash pin below, which ties the gated + deployed WASM to the audited one.

Metadata is extracted with `subwasm` (chevdor), from a WASM file or a live node URL.
"""
import argparse
import hashlib
import json
import subprocess
import sys

_MAX_DEPTH = 24
_SIG_HASH_OVER = 80


def _resolve_source(source: str):
    """ws:// -> a local .wasm. Returns (path, tempfile_or_None).

    subwasm 0.21.3 CORE DUMPS on a ws:// argument, so the documented
    `--old ws://node` invocation in README:101-105 has never worked. Every
    ceremony script already reads the live `:code` (0x3a636f6465) over RPC
    instead; doing it here means the CLI, emit_manifest and any ceremony
    preflight all get the working path without each reimplementing it.
    """
    if not source.startswith(("ws://", "wss://")):
        return source, None
    import tempfile
    from substrateinterface import SubstrateInterface
    sub = SubstrateInterface(url=source)
    try:
        code_hex = sub.rpc_request("state_getStorage", ["0x3a636f6465"])["result"]
    finally:
        sub.close()
    if not code_hex:
        raise RuntimeError(f"{source} returned no :code storage")
    tf = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tf.write(bytes.fromhex(code_hex[2:]))
    tf.flush()
    return tf.name, tf


def _run_subwasm_metadata_v14(subwasm: str, source: str) -> dict:
    source, _tmp = _resolve_source(source)
    out = subprocess.run(
        [subwasm, "metadata", source, "--format", "json"],
        capture_output=True, text=True, timeout=180,
    )
    if out.returncode != 0:
        raise RuntimeError(f"subwasm metadata failed for {source}: {out.stderr[:400]}")
    doc = json.loads(out.stdout)
    if "V14" not in doc:
        raise RuntimeError(f"expected V14 metadata, got keys {list(doc)[:3]}")
    return doc["V14"]


def _canonical(by_id: dict, tid, seen: frozenset, depth: int) -> str:
    """Fully structural type string: primitives + containers expand, and a named
    composite/variant recurses into its fields/variants (so an internal retype
    changes the string). Cycle-safe via `seen`; bounded depth. Does NOT fold in
    generic params (a bounded collection's element is already reached through its
    fields; the bound is a const covered by a constant canary), which keeps the
    fingerprint targeted rather than rippling the whole runtime through PhantomData."""
    t = by_id.get(tid) or {}
    path = ".".join(t.get("path") or [])
    if tid in seen or depth > _MAX_DEPTH:
        # Back-reference by PATH, not the raw registry id — the id is rebuilt per
        # compile (RuntimeCall is 132 in one build, 134 in another) and would emit
        # spurious sig-changes on RuntimeCall-bearing privileged calls (Sudo.sudo).
        return f"@{path or tid}"
    defn = t.get("def") or {}
    kind = next(iter(defn), None)
    dv = defn.get(kind) if kind else None
    seen = seen | {tid}
    if kind in ("primitive", "Primitive"):
        return f"P:{dv}"
    if kind in ("sequence", "Sequence"):
        inner = dv.get("type") if isinstance(dv, dict) else dv
        return f"seq[{_canonical(by_id, inner, seen, depth + 1)}]"
    if kind in ("array", "Array"):
        return f"arr[{_canonical(by_id, dv['type'], seen, depth + 1)};{dv.get('len')}]"
    if kind in ("tuple", "Tuple"):
        return "tup(" + ",".join(_canonical(by_id, x, seen, depth + 1) for x in dv) + ")"
    if kind in ("compact", "Compact"):
        inner = dv.get("type") if isinstance(dv, dict) else dv
        return f"cmp({_canonical(by_id, inner, seen, depth + 1)})"
    if kind in ("composite", "Composite"):
        fields = dv.get("fields", [])
        return f"{path}{{" + ",".join(
            f"{f.get('name') or i}:{_canonical(by_id, f['type'], seen, depth + 1)}"
            for i, f in enumerate(fields)) + "}"
    if kind in ("variant", "Variant"):
        vs = dv.get("variants", [])
        return f"{path}|" + ",".join(
            f"{v.get('name')}#{v.get('index')}(" +
            ",".join(f"{f.get('name') or i}:{_canonical(by_id, f['type'], seen, depth + 1)}"
                     for i, f in enumerate(v.get("fields", []))) + ")"
            for v in vs) + "|"
    if kind in ("bitSequence", "BitSequence"):
        store = dv.get("bit_store_type") if isinstance(dv, dict) else None
        order = dv.get("bit_order_type") if isinstance(dv, dict) else None
        s = _canonical(by_id, store, seen, depth + 1) if store is not None else "_"
        o = _canonical(by_id, order, seen, depth + 1) if order is not None else "_"
        return f"bits:{path}<{s}/{o}>"
    return path or (kind or "?")


def _type_str(by_id: dict, tid) -> str:
    """Structural fingerprint of a type; hashed when long so diff output stays
    bounded while still changing iff the structure changes."""
    c = _canonical(by_id, tid, frozenset(), 0)
    return c if len(c) <= _SIG_HASH_OVER else "sha:" + hashlib.sha256(c.encode()).hexdigest()[:16]


def _variant_map(by_id: dict, ty_id):
    """{variant_name: {index, sig}} for a call/event/error enum; sig is the ordered,
    named, structural fingerprint of its fields (so an added variant, a retyped
    payload, or a reordered field is all visible)."""
    if ty_id is None:
        return {}
    v = (by_id.get(ty_id) or {}).get("def", {}).get("variant")
    if not v:
        return {}
    out = {}
    for x in v["variants"]:
        sig = ",".join(f"{f.get('name') or i}:{_type_str(by_id, f['type'])}"
                       for i, f in enumerate(x.get("fields", [])))
        out[x["name"]] = {"index": x["index"], "sig": sig}
    return out


def reduced_from_v14(meta_v14: dict) -> dict:
    raw_types = meta_v14.get("types")
    types = raw_types["types"] if isinstance(raw_types, dict) else raw_types
    by_id = {t["id"]: t["type"] for t in types}

    def const_hex(value):
        return bytes(value).hex() if isinstance(value, list) else str(value)

    def storage_type_str(entry):
        """Fingerprint a storage entry's full shape: value/key type AND the
        modifier (Default/Optional read semantics), the SCALE default bytes (a
        kill-switch default 0x00->0x01 is a real change), and map hashers (a
        Blake2_128Concat->Identity downgrade enables key-preimage/collision)."""
        ty = entry.get("ty") or {}
        plain = ty.get("Plain", ty.get("plain"))
        if plain is not None:
            core = f"Plain<{_type_str(by_id, plain)}>"
        else:
            m = ty.get("Map", ty.get("map"))
            core = (f"Map<[{','.join(m.get('hashers') or [])}]{_type_str(by_id, m.get('key'))}"
                    f"=>{_type_str(by_id, m.get('value'))}>") if m else "?"
        mod = entry.get("modifier", "")
        default = entry.get("default")
        dflt = bytes(default).hex() if isinstance(default, list) else str(default)
        return f"{core}|mod:{mod}|def:{dflt}"

    pallets = {}
    for p in meta_v14["pallets"]:
        calls = p.get("calls")
        entries = (p.get("storage") or {}).get("entries") or []
        cmap = _variant_map(by_id, calls["ty"]) if calls else {}
        event = p.get("event") or p.get("events")
        error = p.get("error") or p.get("errors")
        pallets[p["name"]] = {
            "index": p["index"],
            "calls": {n: v["index"] for n, v in cmap.items()},
            "call_sigs": {n: v["sig"] for n, v in cmap.items()},
            "constants": {c["name"]: const_hex(c["value"]) for c in (p.get("constants") or [])},
            "storage": sorted(s["name"] for s in entries),
            "storage_types": {s["name"]: storage_type_str(s) for s in entries},
            "events": _variant_map(by_id, event["ty"]) if event else {},
            "errors": _variant_map(by_id, error["ty"]) if error else {},
        }

    # The extrinsic signing envelope: its format version, and the on-wire Address /
    # Signature types (carried as the UncheckedExtrinsic type's generic params). A
    # v4->v5 format bump, MultiAddress->AccountId20, or MultiSignature->EthereumSignature
    # re-encodes EVERY signed tx and breaks offline/hardware signers.
    ext = meta_v14.get("extrinsic") or {}
    ext_ty = ext.get("ty") if isinstance(ext.get("ty"), int) else ext.get("type")
    addr_fp = sig_fp = "?"
    for p in (by_id.get(ext_ty) or {}).get("params") or []:
        if p.get("type") is None:
            continue
        if p.get("name") == "Address":
            addr_fp = _type_str(by_id, p["type"])
        elif p.get("name") == "Signature":
            sig_fp = _type_str(by_id, p["type"])

    def se_fp(s):
        if not isinstance(s, dict):
            return str(s)
        ty = s.get("ty") if isinstance(s.get("ty"), int) else s.get("type")
        add = s.get("additionalSigned") if isinstance(s.get("additionalSigned"), int) else s.get("additional_signed")
        return (f"{s.get('identifier')}:{_type_str(by_id, ty) if ty is not None else '_'}"
                f":{_type_str(by_id, add) if add is not None else '_'}")

    se = ext.get("signedExtensions") or ext.get("signed_extensions") or []
    return {
        "pallets": pallets,
        "signed_extensions": [se_fp(s) for s in se],
        "extrinsic": {"version": ext.get("version"), "address": addr_fp, "signature": sig_fp},
    }


def extract_reduced(source: str, subwasm: str) -> dict:
    return reduced_from_v14(_run_subwasm_metadata_v14(subwasm, source))


def extract_runtime_version(source: str, subwasm: str) -> dict:
    source, _tmp = _resolve_source(source)   # ws:// -> temp .wasm; see _resolve_source
    out = subprocess.run([subwasm, "info", source, "--json"],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError(f"subwasm info failed for {source}: {out.stderr[:400]}")
    doc = json.loads(out.stdout)
    cv = doc.get("core_version") or {}
    return {
        "specName": cv.get("specName"),
        "specVersion": cv.get("specVersion"),
        "transactionVersion": cv.get("transactionVersion"),
        "stateVersion": cv.get("stateVersion"),
        "metadataVersion": doc.get("metadata_version"),
        "apis": sorted(f"{a[0]}:{a[1]}" for a in (cv.get("apis") or []) if isinstance(a, (list, tuple)) and len(a) == 2),
    }


def _variant_delta(old: dict, new: dict) -> dict:
    added = {k: new[k] for k in new.keys() - old.keys()}
    removed = {k: old[k] for k in old.keys() - new.keys()}
    changed = {k: [old[k], new[k]] for k in old.keys() & new.keys() if old[k] != new[k]}
    d = {}
    if added: d["added"] = added
    if removed: d["removed"] = removed
    if changed: d["changed"] = changed
    return d


def compute_diff(old: dict, new: dict) -> dict:
    op, np_ = old["pallets"], new["pallets"]
    both = set(op) & set(np_)
    d = {
        "pallets_added": {n: np_[n] for n in np_.keys() - op.keys()},  # FULL surface
        "pallets_removed": {n: op[n]["index"] for n in op.keys() - np_.keys()},
        "pallet_index_changed": {n: [op[n]["index"], np_[n]["index"]]
                                 for n in both if op[n]["index"] != np_[n]["index"]},
        "calls_added": {}, "calls_removed": {}, "call_index_changed": {},
        "call_sig_changed": {}, "constants_changed": {},
        "storage_added": {}, "storage_removed": {}, "storage_type_changed": {},
        "events_changed": {}, "errors_changed": {},
    }
    for n in both:
        oc, nc = op[n]["calls"], np_[n]["calls"]
        nsig = np_[n]["call_sigs"]
        # An ADDED call carries its index AND signature — else a call added to an
        # existing pallet (spec-234's break-glass setters) could ship any ABI.
        added = {k: {"index": nc[k], "sig": nsig.get(k, "")} for k in nc.keys() - oc.keys()}
        removed = {k: oc[k] for k in oc.keys() - nc.keys()}
        idx_ch = {k: [oc[k], nc[k]] for k in set(oc) & set(nc) if oc[k] != nc[k]}
        if added: d["calls_added"][n] = added
        if removed: d["calls_removed"][n] = removed
        if idx_ch: d["call_index_changed"][n] = idx_ch

        osig = op[n]["call_sigs"]
        sig_ch = {k: [osig[k], nsig[k]] for k in set(osig) & set(nsig) if osig[k] != nsig[k]}
        if sig_ch: d["call_sig_changed"][n] = sig_ch

        ok, nk = op[n]["constants"], np_[n]["constants"]
        cch = {k: [ok.get(k), nk.get(k)] for k in set(ok) | set(nk) if ok.get(k) != nk.get(k)}
        if cch: d["constants_changed"][n] = cch

        os_, ns_ = set(op[n]["storage"]), set(np_[n]["storage"])
        ost, nst = op[n]["storage_types"], np_[n]["storage_types"]
        # ADDED storage carries its full value-type fingerprint (type/default/
        # hasher/modifier) — else e.g. #491 PinnedCommittee could be retyped.
        if ns_ - os_: d["storage_added"][n] = {k: nst.get(k, "") for k in ns_ - os_}
        if os_ - ns_: d["storage_removed"][n] = sorted(os_ - ns_)
        st_ch = {k: [ost[k], nst[k]] for k in set(ost) & set(nst) if ost[k] != nst[k]}
        if st_ch: d["storage_type_changed"][n] = st_ch

        ev = _variant_delta(op[n]["events"], np_[n]["events"])
        if ev: d["events_changed"][n] = ev
        er = _variant_delta(op[n]["errors"], np_[n]["errors"])
        if er: d["errors_changed"][n] = er

    ose, nse = old.get("signed_extensions", []), new.get("signed_extensions", [])
    if ose != nse:
        d["signed_extensions_changed"] = {"from": ose, "to": nse}
    oe, ne = old.get("extrinsic", {}), new.get("extrinsic", {})
    if oe != ne:
        d["extrinsic_changed"] = {"from": oe, "to": ne}
    return d


def _norm(v):
    if isinstance(v, list):
        return sorted(v, key=json.dumps) if v and isinstance(v[0], (dict, list)) else sorted(v)
    return v


def _norm_section(section: dict) -> dict:
    return {k: _norm(v) for k, v in (section or {}).items() if v not in ({}, [], None)}


_SECTIONS = [
    "pallets_added", "pallets_removed", "pallet_index_changed",
    "calls_added", "calls_removed", "call_index_changed", "call_sig_changed",
    "constants_changed", "storage_added", "storage_removed", "storage_type_changed",
    "events_changed", "errors_changed",
]


def assert_matches_expectation(diff: dict, manifest: dict) -> list:
    violations = []
    for s in _SECTIONS:
        actual = _norm_section(diff.get(s, {}))
        expected = _norm_section(manifest.get(s, {}))
        for k in sorted(set(actual) - set(expected)):
            violations.append(f"UNEXPECTED {s}: {k} = {actual[k]!r} (not declared)")
        for k in sorted(set(expected) - set(actual)):
            violations.append(f"MISSING declared {s}: {k} (expected {expected[k]!r})")
        for k in sorted(set(actual) & set(expected)):
            if actual[k] != expected[k]:
                violations.append(f"MISMATCH {s}.{k}: actual {actual[k]!r} != declared {expected[k]!r}")
    for key in ("signed_extensions_changed", "extrinsic_changed"):
        da, de = diff.get(key), manifest.get(key)
        if da != de:
            violations.append(f"{key}: actual {da!r} != declared {de!r}")
    return violations


def check_canaries(new: dict, canaries: dict) -> list:
    violations = []
    for key, want in (canaries or {}).items():
        pallet, const = key.split(".", 1)
        hexval = new["pallets"].get(pallet, {}).get("constants", {}).get(const)
        if hexval is None:
            violations.append(f"CANARY {key}: constant missing from new WASM")
            continue
        got = int.from_bytes(bytes.fromhex(hexval), "little")
        if got != want:
            violations.append(f"CANARY {key}: new WASM has {got} != expected {want}")
    return violations


# The consensus-authority pallets. A construct_runtime! add/remove/rename or an
# authority-storage retype zeroes the live set at the switch block BEFORE Executive
# runs any paired re-seed migration -> immediate production halt (P1-g). OrinqReceipts
# is the app committee pallet (its calls change legitimately) so it is NOT here; its
# committee STORAGE is guarded via the canary + bound-shrink checks.
_AUTHORITY_PALLETS = frozenset({"Aura", "Grandpa", "Session", "SessionCommitteeManagement"})


def check_authority_pallets(diff: dict, manifest: dict) -> list:
    # P1-g: any structural change to a core authority pallet is a hard block unless a
    # try-runtime-proven paired re-seed migration is explicitly attested.
    touched = set()
    for sec in ("pallets_added", "pallets_removed", "pallet_index_changed",
                "storage_added", "storage_removed", "storage_type_changed",
                "calls_removed", "call_index_changed"):
        touched |= set(diff.get(sec, {}) or {}) & _AUTHORITY_PALLETS
    if touched and not manifest.get("authority_reseed_verified"):
        return [f"AUTHORITY-PALLET CHANGE on {sorted(touched)} without authority_reseed_verified — a "
                f"construct_runtime! add/remove/rename or authority-storage retype zeroes the set at the "
                f"switch block, BEFORE Executive runs any paired re-seed (P1-g, the v3->v4 reset class); "
                f"declare authority_reseed_verified only with a try-runtime-proven paired re-seed migration"]
    return []


def check_bound_shrink(old: dict, new: dict, manifest: dict) -> list:
    # P1-h: substrate-interface decodes bounded collections LENIENTLY, so a preflight
    # sees the real live count while the runtime ValueQuery-decodes an over-bound value
    # to EMPTY -> silent authority/committee wipe (hit spec-214 + spec-217). Any tracked
    # bound that DECREASES is a hard block until the live RAW SCALE length is attested <= new.
    v = []
    attested = set(manifest.get("bound_shrink_attested") or [])
    for key in (manifest.get("canaries") or {}):
        pal, const = key.split(".", 1)
        oh = old.get("pallets", {}).get(pal, {}).get("constants", {}).get(const)
        nh = new.get("pallets", {}).get(pal, {}).get("constants", {}).get(const)
        if oh is None or nh is None:
            continue
        ov = int.from_bytes(bytes.fromhex(oh), "little")
        nv = int.from_bytes(bytes.fromhex(nh), "little")
        if nv < ov and key not in attested:
            v.append(f"BOUND SHRINK {key}: {ov} -> {nv} — a bounded-collection bound decreased; substrate-interface "
                     f"decodes leniently so preflight sees the real count while the runtime ValueQuery-decodes to "
                     f"EMPTY (P1-h, hit spec-214/217). Attest bound_shrink_attested only after verifying the LIVE "
                     f"raw-SCALE element count <= {nv}")
    return v


def check_runtime_version(old_rv: dict, new_rv: dict, manifest: dict, diff: dict) -> list:
    v = []
    if new_rv.get("specName") != old_rv.get("specName"):
        v.append(f"SPEC_NAME changed {old_rv.get('specName')!r} -> {new_rv.get('specName')!r} — wrong chain runtime")
    if manifest.get("spec_from") is not None and old_rv.get("specVersion") != manifest["spec_from"]:
        v.append(f"SPEC_VERSION live is {old_rv.get('specVersion')} != declared spec_from {manifest['spec_from']}")
    if manifest.get("spec_to") is not None and new_rv.get("specVersion") != manifest["spec_to"]:
        v.append(f"SPEC_VERSION new WASM is {new_rv.get('specVersion')} != declared spec_to {manifest['spec_to']}")
    osv, nsv = old_rv.get("specVersion"), new_rv.get("specVersion")
    if isinstance(osv, int) and isinstance(nsv, int) and nsv <= osv:
        v.append(f"SPEC_VERSION must strictly increase for a forkless upgrade: {osv} -> {nsv}")
    if new_rv.get("metadataVersion") != old_rv.get("metadataVersion"):
        v.append(f"METADATA_VERSION changed {old_rv.get('metadataVersion')} -> {new_rv.get('metadataVersion')}")
    osv, nsv = old_rv.get("stateVersion"), new_rv.get("stateVersion")
    if osv is not None and nsv is not None and osv != nsv and manifest.get("state_version_to") != nsv:
        v.append(f"STATE_VERSION (state-trie layout) changed {osv} -> {nsv} — this rehashes storage values >32B and "
                 f"diverges the state root without a matching frame_system state-migration; declare state_version_to "
                 f"only with a reviewed migration")
    oa, na = old_rv.get("apis"), new_rv.get("apis")
    if oa is not None and na is not None and oa != na:
        actual = {"added": sorted(set(na) - set(oa)), "removed": sorted(set(oa) - set(na))}
        declared = manifest.get("apis_changed")
        if declared != actual:  # exact set match, not a truthy waiver
            v.append(f"RUNTIME_APIS changed {actual} != declared {declared!r} — a removed/version-bumped runtime "
                     f"API breaks off-chain tooling (cert-daemon, explorers); declare the exact added/removed set")
    otx, ntx = old_rv.get("transactionVersion"), new_rv.get("transactionVersion")
    # A pallet index shift re-encodes EVERY call in that pallet (its leading
    # prefix byte moves); removing a pallet invalidates its calls' encodings.
    # Both are call-encoding changes and MUST bump transaction_version.
    encoding_changed = (any(diff.get(s) for s in
                            ("calls_added", "calls_removed", "call_index_changed", "call_sig_changed",
                             "pallet_index_changed", "pallets_removed"))
                        or bool(diff.get("signed_extensions_changed"))
                        or bool(diff.get("extrinsic_changed")))
    # The must-bump check is UNCONDITIONAL: declaring tx_version_to == the current
    # value must NOT waive it. A call/signed-extension encoding change requires the
    # runtime transaction_version to strictly increase (offline/HW signers key
    # cached metadata on it), regardless of what the manifest declares.
    if encoding_changed and not (isinstance(otx, int) and isinstance(ntx, int) and ntx > otx):
        v.append(f"TX_VERSION: the diff changes call/signed-extension encoding but transaction_version did "
                 f"not strictly increase ({otx} -> {ntx}) — offline/hardware signers key cached metadata on it")
    if manifest.get("tx_version_to") is not None:
        if ntx != manifest["tx_version_to"]:
            v.append(f"TX_VERSION new {ntx} != declared tx_version_to {manifest['tx_version_to']}")
    elif not encoding_changed and otx != ntx:
        v.append(f"TX_VERSION changed {otx} -> {ntx} but not declared and no encoding change — declare tx_version_to")
    return v


def check_code_hash(new_wasm: str, manifest: dict) -> list:
    want = manifest.get("code_hash")
    if not want:
        return ["CODE_HASH: manifest declares no code_hash — REQUIRED for a never-reset ceremony. Pin the "
                "audited artifact's blake2_256 and verify the on-chain authorize_upgrade target matches it "
                "(the only defense against a metadata-invisible swapped call body / origin flip)"]
    h = hashlib.blake2b(digest_size=32)
    with open(new_wasm, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = "0x" + h.hexdigest()
    if got.lower() != want.lower():
        return [f"CODE_HASH new WASM blake2_256 {got} != audited artifact code_hash {want} — "
                f"the file being gated is NOT the audited artifact"]
    return []


def run_gate(old_source: str, new_wasm: str, manifest: dict, subwasm: str) -> list:
    old = extract_reduced(old_source, subwasm)
    new = extract_reduced(new_wasm, subwasm)
    diff = compute_diff(old, new)
    old_rv = extract_runtime_version(old_source, subwasm)
    new_rv = extract_runtime_version(new_wasm, subwasm)
    return (check_code_hash(new_wasm, manifest)
            + check_runtime_version(old_rv, new_rv, manifest, diff)
            + assert_matches_expectation(diff, manifest)
            + check_canaries(new, manifest.get("canaries", {}))
            + check_authority_pallets(diff, manifest)
            + check_bound_shrink(old, new, manifest))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--old", required=True, help="live runtime: a .wasm path or ws://node URL")
    p.add_argument("--new", required=True, help="the new upgrade .wasm")
    p.add_argument("--manifest", required=True, help="expectation manifest JSON")
    p.add_argument("--subwasm", default="subwasm", help="path to the subwasm binary")
    args = p.parse_args()
    manifest = json.load(open(args.manifest))
    violations = run_gate(args.old, args.new, manifest, args.subwasm)
    if violations:
        print("CEREMONY GATE: FAIL — refusing to authorize_upgrade\n", file=sys.stderr)
        for v in violations:
            print(f"  ✗ {v}", file=sys.stderr)
        print("\nNOTE: metadata cannot see dispatch origins or call-body logic. Even on PASS, a source/commit "
              "diff of the exact tree (audit every ensure_root/ensure_origin site) is MANDATORY.", file=sys.stderr)
        sys.exit(1)
    print("CEREMONY GATE: PASS — new WASM diff matches the declared expectation, canaries intact, code_hash "
          "matches the audited artifact.\nREMINDER: run the source/commit diff too — metadata cannot see "
          "ensure_root->ensure_signed origin flips or swapped call bodies.")


if __name__ == "__main__":
    main()
