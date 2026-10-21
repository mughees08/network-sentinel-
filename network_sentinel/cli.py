"""Command-line interface for Network Sentinel."""
import argparse
import csv
import json
import sys
from pathlib import Path

from .analyzer import analyze_pcap


def _write_reports(report: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    csv_path = out_dir / "protocols.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["protocol", "packet_count"])
        writer.writerows(report["protocols"].items())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-sentinel",
        description="Analyze an authorized PCAP/PCAPNG capture offline.",
    )
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--syn-threshold", type=int, default=20,
                        help="Initial SYN packet threshold per source (default: 20)")
    parser.add_argument("--dns-threshold", type=int, default=50,
                        help="DNS query threshold for the capture (default: 50)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.syn_threshold < 1 or args.dns_threshold < 1:
        parser.error("thresholds must be positive integers")
    try:
        report = analyze_pcap(args.capture, args.syn_threshold, args.dns_threshold)
        _write_reports(report, Path(args.out))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print("Network Sentinel — analysis complete")
    print(f"Capture: {report['capture']}")
    print(f"Packets: {summary['packet_count']} | Bytes: {summary['total_bytes']}")
    print(f"Alerts: {len(report['alerts'])}")
    print(f"JSON report: {Path(args.out) / 'report.json'}")
    print(f"Protocol CSV: {Path(args.out) / 'protocols.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
