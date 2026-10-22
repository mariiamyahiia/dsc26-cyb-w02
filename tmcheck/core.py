"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections import Counter
from dataclasses import dataclass

import yaml

STRIDE = ("S", "T", "R", "I", "D", "E")
KINDS = ("external_entity", "process", "data_store")
STATUSES = ("open", "mitigated", "accepted")
SECURE_PROTOCOLS = {"https", "tls", "mtls", "sftp", "ssh"}
SECTIONS = ("zones", "elements", "flows", "threats")

class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"

#helpers
def _items(model: dict, key: str) -> list[dict]:
    seq = model.get(key) or []
    return [x for x in seq if isinstance(x, dict)]


def _zone_of(model: dict) -> dict:
    return {e.get("id"): e.get("zone") for e in _items(model, "elements")}


def _is_score(v) -> bool:
    # type(v) is int rejects True/False (bool subclasses int) and 4.0
    return type(v) is int and 1 <= v <= 5


def _has_text(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _natural_key(s) -> list:
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", str(s))]


def load_model(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # OSError, UnicodeError, yaml.YAMLError (incl. unsafe tags)
        raise ModelError(f"cannot load {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelError("top level of the model must be a mapping")
    for name in SECTIONS:
        value = data.get(name)
        if value is None:
            data[name] = []
        elif not isinstance(value, list):
            raise ModelError(f"section '{name}' must be a list")
    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        cats = {"T", "I", "D"}
        if is_log:
            cats.add("R")
        return cats
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown kind: {kind!r}")


def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()
    zones = _items(model, "zones")
    elements = _items(model, "elements")
    flows = _items(model, "flows")
    threats = _items(model, "threats")

    all_ids = [i.get("id") for grp in (zones, elements, flows, threats)
               for i in grp if i.get("id") is not None]
    for ident, n in Counter(all_ids).items():
        if n > 1:
            issues.add(Issue(str(ident), "DUPLICATE_ID", f"id used {n} times"))

    zone_ids = {z.get("id") for z in zones}
    elem = {}
    for e in elements:
        elem.setdefault(e.get("id"), e)
    flow_ids = {f.get("id") for f in flows}

    for e in elements:
        ref = str(e.get("id"))
        if e.get("kind") not in KINDS:
            issues.add(Issue(ref, "BAD_KIND", f"bad kind {e.get('kind')!r}"))
        if e.get("zone") not in zone_ids:
            issues.add(Issue(ref, "UNKNOWN_ZONE", f"unknown zone {e.get('zone')!r}"))

    for f in flows:
        ref = str(f.get("id"))
        src, tgt = f.get("source"), f.get("target")
        if src not in elem or tgt not in elem:
            issues.add(Issue(ref, "UNKNOWN_REF", "source or target is not an element"))
        elif src == tgt or "process" not in (elem[src].get("kind"), elem[tgt].get("kind")):
            issues.add(Issue(ref, "INVALID_FLOW", "a flow needs a process at one end"))

    for t in threats:
        ref = str(t.get("id"))
        target = t.get("target")
        kind, is_log = None, False
        if target in elem:
            kind = elem[target].get("kind")
            is_log = elem[target].get("is_log") is True
        elif target in flow_ids:
            kind = "data_flow"
        else:
            issues.add(Issue(ref, "UNKNOWN_REF", f"unknown target {target!r}"))

        cat = t.get("category")
        if not (isinstance(cat, str) and cat in STRIDE):
            issues.add(Issue(ref, "BAD_CATEGORY", f"bad category {cat!r}"))
        elif kind is not None and (kind == "data_flow" or kind in KINDS):
            if cat not in applicable(kind, is_log=is_log):
                issues.add(Issue(ref, "INAPPLICABLE_CATEGORY",
                                 f"{cat} does not apply to {kind}"))

        if not (_is_score(t.get("likelihood")) and _is_score(t.get("impact"))):
            issues.add(Issue(ref, "BAD_SCORE", "likelihood/impact must be int 1-5"))

        status = t.get("status")
        if status not in STATUSES:
            issues.add(Issue(ref, "BAD_STATUS", f"bad status {status!r}"))
        elif status == "mitigated" and not _has_text(t.get("mitigation")):
            issues.add(Issue(ref, "MISSING_MITIGATION", "mitigated needs mitigation text"))
        elif status == "accepted" and not _has_text(t.get("justification")):
            issues.add(Issue(ref, "MISSING_JUSTIFICATION", "accepted needs justification"))

    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    zone_of = _zone_of(model)
    out = []
    for f in _items(model, "flows"):
        s, t = f.get("source"), f.get("target")
        if s in zone_of and t in zone_of and zone_of[s] != zone_of[t]:
            out.append(f.get("id"))
    return out



def coverage_gaps(model: dict) -> list[Gap]:
    elem = {}
    for e in _items(model, "elements"):
        elem.setdefault(e.get("id"), e)
    flows = {f.get("id"): f for f in _items(model, "flows")}

    scope: dict = {}  # ref -> set of applicable categories
    for fid in crossing_flows(model):
        scope[fid] = applicable("data_flow")
        for end in (flows[fid].get("source"), flows[fid].get("target")):
            e = elem[end]
            if e.get("kind") in KINDS:
                scope[end] = applicable(e["kind"], is_log=e.get("is_log") is True)

    covered = {(t.get("target"), t.get("category")) for t in _items(model, "threats")}
    gaps = [Gap(str(ref), c)
            for ref, cats in scope.items()
            for c in cats if (ref, c) not in covered]
    return sorted(gaps, key=lambda g: (g.ref, STRIDE.index(g.category)))

def policy_findings(model: dict) -> list[Issue]:
    out: set[Issue] = set()
    zone_of = _zone_of(model)
    trust = {z.get("id"): z.get("trust") for z in _items(model, "zones")}
    flows = {f.get("id"): f for f in _items(model, "flows")}

    for fid in crossing_flows(model):
        f = flows[fid]
        proto = f.get("protocol")
        if not (isinstance(proto, str) and proto.casefold() in SECURE_PROTOCOLS):
            out.add(Issue(str(fid), "UNENCRYPTED_CROSSING", f"protocol {proto!r}"))
        ts = trust.get(zone_of[f["source"]])
        tt = trust.get(zone_of[f["target"]])
        if (isinstance(ts, int) and isinstance(tt, int) and tt > ts
                and f.get("authenticated") is not True):
            out.add(Issue(str(fid), "UNAUTHENTICATED_INBOUND", "inbound flow not authenticated"))

    has_i = {t.get("target") for t in _items(model, "threats") if t.get("category") == "I"}
    for e in _items(model, "elements"):
        if (e.get("kind") == "data_store" and e.get("holds_pii") is True
                and e.get("id") not in has_i):
            out.add(Issue(str(e.get("id")), "PII_STORE_WITHOUT_I_THREAT",
                          "store holds PII but has no I threat"))
    return sorted(out, key=lambda i: (i.ref, i.code, i.message))


def rank(model: dict) -> list[RankedThreat]:
    rows = []
    for t in _items(model, "threats"):
        if t.get("status") != "open":
            continue
        l, i = t.get("likelihood"), t.get("impact")
        if not (_is_score(l) and _is_score(i)):
            continue
        score = l * i
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"
        rows.append((score, i, t.get("id"), level))
    rows.sort(key=lambda r: (-r[0], -r[1], _natural_key(r[2])))
    return [RankedThreat(str(tid), score, level) for score, _, tid, level in rows]
