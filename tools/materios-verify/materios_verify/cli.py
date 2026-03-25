"""CLI entry point for materios-verify."""

import argparse
import json
import os
import sys

from .core import VerificationResult, verify_receipt

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _pass(msg: str):
    print(f"  {GREEN}PASS{RESET}  {msg}")


def _fail(msg: str):
    print(f"  {RED}FAIL{RESET}  {msg}")


def _warn(msg: str):
    print(f"  {YELLOW}WARN{RESET}  {msg}")


def _info(msg: str):
    print(f"  {CYAN}INFO{RESET}  {msg}")


def _short(h: str, n: int = 18) -> str:
    if len(h) > n + 4:
        return h[:n] + "..."
    return h


def print_report(report, verbose: bool = False):
    """Print a VerificationReport in human-readable format."""
    print(f"\n{BOLD}=== Materios Checkpoint Verifier ==={RESET}")
    print(f"  Receipt ID : {report.receipt_id}")
    print(f"  RPC URL    : {report.rpc_url}")
    print()

    for step in report.steps:
        print(f"{BOLD}[{step.step}/7] {step.title}{RESET}")
        if step.passed:
            _pass(step.title)
        else:
            if "error" in step.details:
                _fail(step.details["error"])
            elif step.warnings:
                for w in step.warnings:
                    _warn(w)
            else:
                _fail(step.title)

        if verbose:
            for k, v in step.details.items():
                if k != "error":
                    _info(f"{k:20s}: {v}")

        for w in step.warnings:
            if step.passed:
                _warn(w)

        print()

    # Summary
    print(f"{BOLD}=== Verification Summary ==={RESET}")
    print(f"  Receipt ID          : {report.receipt_id}")
    if report.cert_hash:
        print(f"  On-chain cert hash  : {report.cert_hash}")
    if report.leaf_hash:
        print(f"  Checkpoint leaf     : {report.leaf_hash}")
    if report.anchor:
        print(f"  Anchor root         : {report.anchor.get('root_hash', '?')}")
        print(f"  Anchor block        : #{report.anchor.get('block_num', '?')}")
        print(f"  Match type          : {report.anchor.get('match_type', '?')}")

    print()

    if report.result == VerificationResult.FULLY_VERIFIED:
        print(f"  {GREEN}{BOLD}RESULT: FULLY VERIFIED{RESET}")
        print(f"  {DIM}Full chain of custody:{RESET}")
        print(f"  {DIM}  Receipt -> Cert -> Leaf -> Merkle Root -> Anchor{RESET}")
    elif report.result == VerificationResult.PARTIALLY_VERIFIED:
        print(f"  {YELLOW}{BOLD}RESULT: PARTIALLY VERIFIED{RESET}")
        print(f"  {DIM}Receipt and cert valid. Checkpoint anchor not yet found.{RESET}")
    else:
        print(f"  {RED}{BOLD}RESULT: NOT VERIFIED{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Materios end-to-end checkpoint verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  materios-verify 0xabc123...def456
  materios-verify 0xabc123... --rpc-url wss://materios.fluxpointstudios.com/rpc
  materios-verify 0xabc123... --verbose --scan-window 1000
  materios-verify 0xabc123... --json
        """,
    )
    parser.add_argument(
        "receipt_id",
        help="Receipt ID to verify (hex, with or without 0x prefix)",
    )
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("MATERIOS_RPC_URL", "ws://127.0.0.1:9944"),
        help="Materios chain RPC URL (default: $MATERIOS_RPC_URL or ws://127.0.0.1:9944)",
    )
    parser.add_argument(
        "--chain-id",
        default=os.environ.get("CHAIN_ID", ""),
        help="Chain ID (genesis hash hex)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed values",
    )
    parser.add_argument(
        "--scan-window", type=int, default=500,
        help="Blocks to scan for events (default: 500)",
    )
    parser.add_argument(
        "--checkpoint-state", default=None,
        help="Path to checkpoint-state.json",
    )
    parser.add_argument(
        "--checkpoint-history", default=None,
        help="Path to checkpoint-history.json for multi-leaf proofs",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output JSON instead of human-readable text",
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        global GREEN, RED, YELLOW, CYAN, BOLD, DIM, RESET
        GREEN = RED = YELLOW = CYAN = BOLD = DIM = RESET = ""

    report = verify_receipt(
        receipt_id=args.receipt_id,
        rpc_url=args.rpc_url,
        chain_id_override=args.chain_id if args.chain_id else None,
        scan_window=args.scan_window,
        checkpoint_state_path=args.checkpoint_state,
        checkpoint_history_path=args.checkpoint_history,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report, verbose=args.verbose)

    sys.exit(0 if report.result == VerificationResult.FULLY_VERIFIED else 1)


if __name__ == "__main__":
    main()
