"""flaghunter command line interface."""
import argparse
import sys

from .pcaphunt import hunt_pcap, render_json, render_markdown
from .solver import render_markdown as solve_markdown
from .solver import solve_file


def _cmd_solve(args: argparse.Namespace) -> int:
    report = solve_file(args.file)
    print(solve_markdown(report))
    return 0


def _cmd_pcap(args: argparse.Namespace) -> int:
    try:
        report = hunt_pcap(args.file, key_len=args.key_len, pattern=args.pattern)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(render_json(report))
    else:
        print(render_markdown(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flaghunter",
        description="CTF crypto autosolver and pcap hunter. Runs the attack battery so you don't have to.")
    sub = parser.add_subparsers(dest="command", required=True)

    solve = sub.add_parser("solve", help="run the attack battery against a challenge file")
    solve.add_argument("file", help="challenge file to analyze")
    solve.set_defaults(func=_cmd_solve)

    pcap_cmd = sub.add_parser("pcap", help="hunt a packet capture for tokens and obfuscated blobs")
    pcap_cmd.add_argument("file", help="pcap file to analyze")
    pcap_cmd.add_argument("--key-len", type=int, default=12,
                          help="length of alpha tokens to hunt (default 12)")
    pcap_cmd.add_argument("--pattern", default=None,
                          help="custom regex for token hunting, overrides --key-len")
    pcap_cmd.add_argument("--format", choices=["md", "json"], default="md",
                          help="report format (default md)")
    pcap_cmd.set_defaults(func=_cmd_pcap)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
