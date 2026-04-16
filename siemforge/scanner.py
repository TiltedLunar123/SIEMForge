"""Log scanner -- match Sigma rules against log files.

Supports JSON (array or JSONL), syslog (RFC 3164), and CSV formats.
Condition evaluation uses a safe recursive-descent parser (NO eval).
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

from siemforge.display import C, bullet, err, header, info, ok
from siemforge.mitre import MITRE_MAP


def _parse_json_log(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        data = json.loads(text)
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        return []
    events = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                pass
    return events


_SYSLOG_RE = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)


def _parse_syslog(path: Path) -> list[dict]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SYSLOG_RE.match(line)
        if m:
            events.append({
                "timestamp": m.group("timestamp"),
                "hostname": m.group("hostname"),
                "program": m.group("program"),
                "pid": m.group("pid") or "",
                "message": m.group("message"),
            })
        else:
            events.append({"message": line})
    return events


def _parse_csv_log(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return [dict(row) for row in reader]


def parse_log_file(path: Path, fmt: str | None = None) -> list[dict]:
    path = Path(path)
    if fmt is None:
        suffix = path.suffix.lower()
        if suffix in (".json", ".jsonl"):
            fmt = "json"
        elif suffix in (".log", ".syslog"):
            fmt = "syslog"
        elif suffix == ".csv":
            fmt = "csv"
        else:
            fmt = "json"
    parsers = {"json": _parse_json_log, "syslog": _parse_syslog, "csv": _parse_csv_log}
    parser = parsers.get(fmt)
    if parser is None:
        raise ValueError(f"Unknown log format: {fmt}")
    return parser(path)


# ---- Event matching ----

def _flatten(obj: Any, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, dict):
                out.update(_flatten(v, full))
            else:
                out[full.lower()] = str(v)
    return out


def _match_value(field_val: str, pattern: str, modifiers: list[str]) -> bool:
    fv = field_val.lower()
    pv = str(pattern).lower()
    # Normalise doubled backslashes from YAML quoting to single
    pv = pv.replace("\\\\", "\\")
    if "re" in modifiers:
        try:
            return bool(re.search(pv, fv))
        except re.error:
            return False
    if "contains" in modifiers:
        return pv in fv
    if "endswith" in modifiers:
        return fv.endswith(pv)
    if "startswith" in modifiers:
        return fv.startswith(pv)
    return fv == pv


def _match_selection(event: dict[str, str], selection: dict) -> bool:
    if not isinstance(selection, dict):
        return False
    for raw_key, values in selection.items():
        parts = raw_key.split("|")
        field_name = parts[0].lower()
        modifiers = [m.lower() for m in parts[1:]]
        if not isinstance(values, list):
            values = [values]
        if field_name == "_keyword":
            found = False
            for pv in values:
                for ev in event.values():
                    if _match_value(ev, pv, modifiers or ["contains"]):
                        found = True
                        break
                if found:
                    break
            if not found:
                return False
            continue
        field_val = event.get(field_name, "")
        if not field_val:
            for ek, ev in event.items():
                if ek.endswith(f".{field_name}") or ek == field_name:
                    field_val = ev
                    break
        if not field_val:
            return False
        if not any(_match_value(field_val, pv, modifiers) for pv in values):
            return False
    return True


# ---- Condition parser (SAFE -- no eval) ----

_COND_TOKEN_RE = re.compile(r'\s*(and|or|not|\(|\)|\w+)\s*', re.IGNORECASE)


def _tokenize_condition(condition: str) -> list[str]:
    condition = " ".join(condition.split())
    tokens = _COND_TOKEN_RE.findall(condition)
    return [t for t in tokens if t.strip()]


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    tokens = _tokenize_condition(condition)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance():
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_or():
        left = parse_and()
        while peek() and peek().lower() == "or":
            advance()
            right = parse_and()
            left = left or right
        return left

    def parse_and():
        left = parse_not()
        while peek() and peek().lower() == "and":
            advance()
            right = parse_not()
            left = left and right
        return left

    def parse_not():
        if peek() and peek().lower() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        t = peek()
        if t == "(":
            advance()
            result = parse_or()
            if peek() == ")":
                advance()
            return result
        name = advance()
        return selections.get(name, False)

    if not tokens:
        return False
    return parse_or()


def match_rule(event: dict, rule: dict) -> bool:
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return False
    condition = detection.get("condition", "")
    if not condition:
        return False
    flat = _flatten(event)
    selections: dict[str, bool] = {}
    for key, block in detection.items():
        if key == "condition":
            continue
        if isinstance(block, dict):
            selections[key] = _match_selection(flat, block)
        elif isinstance(block, list):
            selections[key] = any(
                _match_selection(flat, b) for b in block if isinstance(b, dict)
            )
        else:
            selections[key] = False
    cond_str = " ".join(str(condition).split())
    return _eval_condition(cond_str, selections)


# ---- Scan entry point ----

def scan_logs(log_path: str, rules: dict[str, dict],
              fmt: str | None = None, output_json: bool = False):
    path = Path(log_path)
    if not output_json:
        header(f"SCANNING: {log_path}")
    if not path.is_file():
        err(f"Log file not found: {log_path}")
        return -1
    try:
        events = parse_log_file(path, fmt)
    except Exception as exc:
        err(f"Failed to parse {log_path}: {exc}")
        return -1
    if not output_json:
        info(f"Parsed {len(events)} events from {path.name}")
        print()

    alerts: list[dict] = []
    level_colors = {
        "critical": C.RED, "high": C.YELLOW,
        "medium": C.CYAN, "low": C.GREEN,
        "informational": C.DIM,
    }

    for idx, event in enumerate(events):
        for rule_file, rule in rules.items():
            if match_rule(event, rule):
                level = rule.get("level", "unknown")
                title = rule.get("title", rule_file)
                lc = level_colors.get(level, C.WHITE)
                techniques = []
                for tag in rule.get("tags", []):
                    tag_str = str(tag)
                    if tag_str.startswith("attack.t"):
                        tid = tag_str.replace("attack.", "").upper()
                        techniques.append(tid)
                alert = {
                    "event_index": idx,
                    "rule": rule_file,
                    "title": title,
                    "level": level,
                    "techniques": techniques,
                    "event_summary": _summarise_event(event),
                }
                alerts.append(alert)
                if not output_json:
                    print(f"  {lc}[{level.upper()}]{C.RESET} "
                          f"{C.BOLD}{title}{C.RESET}  "
                          f"{C.DIM}({rule_file}){C.RESET}")
                    for tid in techniques:
                        name = MITRE_MAP.get(tid, {}).get("name", "")
                        tactic = MITRE_MAP.get(tid, {}).get("tactic", "")
                        bullet(f"{C.CYAN}{tid}{C.RESET} {name}"
                               + (f"  [{tactic}]" if tactic else ""))
                    summary = _summarise_event(event)
                    if summary:
                        bullet(f"{C.DIM}{summary}{C.RESET}")
                    print()

    if output_json:
        print(json.dumps(alerts, indent=2))
    else:
        total = len(alerts)
        if total:
            print(f"  {C.BOLD}Alerts:{C.RESET} {C.RED}{total}{C.RESET} "
                  f"across {len(events)} events")
        else:
            ok("No alerts -- all events are clean.")

    return len(alerts)


def _summarise_event(event: dict) -> str:
    parts: list[str] = []
    for key in ("CommandLine", "commandline", "message", "Image", "image",
                "TargetImage", "SourceImage"):
        val = event.get(key, "")
        if val:
            text = str(val)[:120]
            parts.append(f"{key}={text}")
            break
    return " | ".join(parts)
