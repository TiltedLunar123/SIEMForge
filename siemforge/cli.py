"""CLI entry point for SIEMForge."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from siemforge._version import VERSION
from siemforge.display import BANNER, DIV, C, header, info
from siemforge.export import (
    export_all,
    export_sigma_rules,
    export_sysmon_config,
    export_wazuh_rules,
)
from siemforge.loader import load_sigma_rules
from siemforge.mitre import show_mitre_coverage
from siemforge.scanner import scan_logs
from siemforge.stats import show_rule_summary, show_stats, show_stats_json
from siemforge.test_commands import generate_test_commands
from siemforge.validator import validate_rules

CONVERT_EXTENSIONS = {"splunk": ".spl", "elastic": ".lucene", "kibana": ".kql"}


def convert_rules(
    rules: dict[str, dict],
    backend_name: str,
    output_dir: str | None = None,
    single_rule: str | None = None,
    dry_run: bool = False,
) -> int:
    """Convert Sigma rules to SIEM queries using the specified backend.

    Returns the number of conversion errors (0 on full success).
    """
    from converters import BACKENDS
    from siemforge.display import _LINE_CHAR, ok
    from siemforge.display import err as _err

    backend_cls = BACKENDS[backend_name]
    converter = backend_cls()
    ext = CONVERT_EXTENSIONS[backend_name]
    errors = 0

    if single_rule:
        if single_rule not in rules:
            _err(f"Rule not found: {single_rule}")
            info("Available rules: " + ", ".join(sorted(rules.keys())))
            return
        rules = {single_rule: rules[single_rule]}

    header("CONVERTING SIGMA RULES \u2192 " + backend_name.upper())

    if output_dir:
        out_path = Path(output_dir)
        if dry_run:
            for filename in rules:
                stem = filename.rsplit(".", 1)[0]
                info(f"Would write {out_path / (stem + ext)}")
            return

        try:
            out_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _err(f"Cannot create directory {output_dir}: {e}")
            return

        for filename, rule in rules.items():
            stem = filename.rsplit(".", 1)[0]
            try:
                query = converter.convert_rule(rule)
            except (ValueError, KeyError) as exc:
                _err(f"Failed to convert {filename}: {exc}")
                errors += 1
                continue
            filepath = out_path / (stem + ext)
            try:
                filepath.write_text(query + "\n", encoding="utf-8")
                ok(f"Wrote {filepath}")
            except OSError as e:
                _err(f"Failed to write {filepath}: {e}")
                errors += 1

        info(f"Exported {len(rules)} queries to ./{out_path}/")
    else:
        for filename, rule in rules.items():
            title = rule.get("title", filename)
            level = rule.get("level", "?")

            technique = ""
            for tag in rule.get("tags", []):
                tag_str = str(tag)
                if tag_str.startswith("attack.t"):
                    technique = tag_str.replace("attack.", "").upper()
                    break

            print(f"\n  {C.BOLD}{C.MAGENTA}\u25b8 {title}{C.RESET} ({filename})")
            meta = f"Level: {level}"
            if technique:
                meta += f" | Technique: {technique}"
            print(f"    {C.DIM}{meta}{C.RESET}")
            print(f"  {C.BLUE}{_LINE_CHAR * 50}{C.RESET}")

            if dry_run:
                info("(dry run -- query not generated)")
            else:
                try:
                    query = converter.convert_rule(rule)
                except (ValueError, KeyError) as exc:
                    _err(f"Failed to convert {filename}: {exc}")
                    errors += 1
                    continue
                for line in query.split("\n"):
                    print(f"    {C.GREEN}{line}{C.RESET}")

    print(f"\n  {C.BOLD}Backend:{C.RESET} {backend_name}")
    print(f"  {C.BOLD}Rules converted:{C.RESET} {len(rules)}")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siemforge",
        description="SIEMForge \u2014 SIEM Detection Content Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m siemforge --export-all          Export everything\n"
            "  python -m siemforge --sigma               Export Sigma rules only\n"
            "  python -m siemforge --validate             Validate all rules\n"
            "  python -m siemforge --mitre               Show MITRE coverage\n"
            "  python -m siemforge --tests               Show test commands\n"
            "  python -m siemforge --stats               Show project stats\n"
            "  python -m siemforge --list                List all rules\n"
            "  python -m siemforge --convert splunk      Convert to Splunk SPL\n"
            "  python -m siemforge --scan LOG            Scan a log file\n"
        ),
    )

    parser.add_argument("--version", "-V", action="version",
                        version=f"SIEMForge v{VERSION}")
    parser.add_argument("--export-all", action="store_true",
                        help="Export all detection content (Sigma + Sysmon + Wazuh)")
    parser.add_argument("--sigma", action="store_true",
                        help="Export Sigma rules to ./sigma_rules/")
    parser.add_argument("--sysmon", action="store_true",
                        help="Export Sysmon configuration to ./sysmon/")
    parser.add_argument("--wazuh", action="store_true",
                        help="Export Wazuh rules and agent config to ./wazuh/")
    parser.add_argument("--validate", action="store_true",
                        help="Validate all Sigma rules for required fields")
    parser.add_argument("--mitre", action="store_true",
                        help="Display MITRE ATT&CK coverage matrix")
    parser.add_argument("--tests", action="store_true",
                        help="Show safe test commands to trigger detections")
    parser.add_argument("--stats", action="store_true",
                        help="Show project statistics")
    parser.add_argument("--list", action="store_true",
                        help="List all detection rules with metadata")
    parser.add_argument("--output-dir", "-o", type=str, default=None,
                        help="Custom output directory for exports")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview what would be exported without writing files")
    parser.add_argument("--json", action="store_true",
                        help="Output statistics in JSON format (machine-readable)")
    parser.add_argument("--convert", type=str, default=None,
                        choices=["splunk", "elastic", "kibana"],
                        help="Convert Sigma rules to SIEM query language")
    parser.add_argument("--convert-output", type=str, default=None,
                        help="Write converted queries to directory (one file per rule)")
    parser.add_argument("--convert-rule", type=str, default=None,
                        help="Convert a single rule by filename")
    parser.add_argument("--scan", type=str, default=None, metavar="LOGFILE",
                        help="Scan a log file against all Sigma rules")
    parser.add_argument("--scan-format", type=str, default=None,
                        choices=["json", "syslog", "csv"],
                        help="Force log format (auto-detected by default)")

    return parser


def main() -> int:
    """Run the SIEMForge CLI. Returns 0 on success, 1 on error."""
    # Enable ANSI on Windows
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
        except Exception:
            pass

    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    # Load rules once
    rules = load_sigma_rules()

    ran_something = False
    errors = 0
    dry_run = args.dry_run

    if args.export_all:
        export_all(rules, output_dir=args.output_dir or "siemforge_export", dry_run=dry_run)
        ran_something = True

    if args.sigma:
        export_sigma_rules(rules, output_dir=args.output_dir or "sigma_rules", dry_run=dry_run)
        ran_something = True

    if args.sysmon:
        export_sysmon_config(output_dir=args.output_dir or "sysmon", dry_run=dry_run)
        ran_something = True

    if args.wazuh:
        export_wazuh_rules(output_dir=args.output_dir or "wazuh", dry_run=dry_run)
        ran_something = True

    if args.validate:
        validate_rules(rules)
        ran_something = True

    if args.mitre:
        show_mitre_coverage(rules)
        ran_something = True

    if args.tests:
        generate_test_commands()
        ran_something = True

    if args.stats:
        if args.json:
            show_stats_json(rules)
        else:
            show_stats(rules)
        ran_something = True

    if args.list:
        show_rule_summary(rules)
        ran_something = True

    if args.convert:
        errors += convert_rules(
            rules,
            backend_name=args.convert,
            output_dir=args.convert_output,
            single_rule=args.convert_rule,
            dry_run=dry_run,
        )
        ran_something = True

    if args.scan:
        try:
            scan_logs(args.scan, rules, fmt=args.scan_format,
                      output_json=args.json)
        except (ValueError, OSError) as exc:
            from siemforge.display import err
            err(str(exc))
            errors += 1
        ran_something = True

    if not ran_something:
        show_stats(rules)
        show_rule_summary(rules)
        hint = "Run with --help for all options or --export-all to export everything."
        print(f"\n  {C.DIM}{hint}{C.RESET}")

    print(f"\n{DIV}")
    print(f"  {C.CYAN}SIEMForge -- Detection engineering made portable.{C.RESET}")
    print(f"{DIV}\n")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
