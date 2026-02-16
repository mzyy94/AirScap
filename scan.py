#!/usr/bin/env python3
"""ScanSnap CLI — discover and scan from the command line."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from scansnap.scanner import Scanner
from scansnap.data import ScanError
from scansnap.discovery import ScanSnapDiscovery
from scansnap.packets import ColorMode, PaperSize, Quality, ScanConfig


async def cmd_discover(args: argparse.Namespace) -> None:
    """Discover scanners on the network."""
    discovery = ScanSnapDiscovery()
    print(f"Local IP: {discovery.local_ip}")
    print("Searching for ScanSnap devices...")

    try:
        if args.ip:
            info = await discovery.find_scanner(scanner_ip=args.ip, timeout=args.timeout)
        else:
            info = await discovery.find_scanner(timeout=args.timeout)

        print(f"\nFound scanner:")
        print(f"  Name:         {info.name}")
        print(f"  Serial:       {info.serial}")
        print(f"  IP:           {info.device_ip}")
        print(f"  MAC:          {info.mac}")
        print(f"  Data Port:    {info.data_port}")
        print(f"  Control Port: {info.control_port}")
        print(f"  Paired:       {info.paired}")
        print(f"  State:        {info.state}")
        if info.client_ip:
            print(f"  Connected To: {info.client_ip}")
    except asyncio.TimeoutError:
        print("No scanner found within timeout.", file=sys.stderr)
        sys.exit(1)


async def cmd_pair(args: argparse.Namespace) -> None:
    """Pair with a scanner."""
    password = getattr(args, "password", None)
    identity = getattr(args, "pair_identity", None)

    if not password and not identity:
        print("Error: --password or --identity is required.", file=sys.stderr)
        sys.exit(1)

    if password:
        print(f"Pairing with password: {password}")
    else:
        print(f"Pairing with identity: {identity}")

    if not args.ip:
        print("Discovering scanner...")

    try:
        scanner, ident = await Scanner.pair(
            password=password,
            identity=identity,
            scanner_ip=args.ip,
            timeout=args.timeout,
        )
        print(f"Paired!")
        print(f"\n  Identity: {ident}")
        print(f"\nUse: python scan.py --ip {scanner.host} --identity {ident} scan")
        await scanner.disconnect()
    except ValueError as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(1)
    except asyncio.TimeoutError:
        print("No scanner found within timeout.", file=sys.stderr)
        sys.exit(1)


async def cmd_scan(args: argparse.Namespace) -> None:
    """Connect and scan."""
    if args.ip:
        scanner = Scanner(host=args.ip, identity=args.identity)
    else:
        print("Discovering scanner...")
        scanner = await Scanner.discover(timeout=args.timeout)
        scanner.identity = args.identity

    print(f"Connecting to {scanner.host}...")
    await scanner.connect()
    print("Connected!")

    config = ScanConfig(
        color_mode=ColorMode[args.color.upper()],
        quality=Quality[args.quality.upper()],
        duplex=not args.simplex,
        bleed_through=args.bleed_through,
        paper_size=PaperSize[args.paper_size.upper()],
        bw_density=args.bw_density,
        multi_feed=args.multi_feed,
        blank_page_removal=args.blank_page_removal,
    )

    output_dir = args.output or "./scanned"
    if args.wait_button:
        print(f"Waiting for button press... (output: {output_dir})")
    else:
        print(f"Starting scan... (output: {output_dir})")

    try:
        files = await scanner.scan_to_files(
            output_dir, config, wait_for_button=args.wait_button,
        )
        print(f"\nScan complete! {len(files)} page(s) saved:")
        for f in files:
            print(f"  {f}")
    except ScanError as e:
        print(f"\nScan error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        await scanner.disconnect()
        print("Disconnected.")



def main() -> None:
    parser = argparse.ArgumentParser(
        description="ScanSnap iX500 network scanner client",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging",
    )
    parser.add_argument(
        "--ip", type=str, default=None, help="Scanner IP address (skip discovery)",
    )
    parser.add_argument(
        "--timeout", type=float, default=30, help="Discovery timeout in seconds",
    )
    parser.add_argument(
        "--identity", type=str, default="",
        help="Pairing identity string (from initial setup)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("discover", help="Find scanners on the network")

    pair_p = sub.add_parser("pair", help="Pair with a scanner")
    pair_group = pair_p.add_mutually_exclusive_group(required=True)
    pair_group.add_argument(
        "--password", type=str, help="Scanner password (e.g. 0700)",
    )
    pair_group.add_argument(
        "--identity", type=str, dest="pair_identity",
        help="Pre-computed identity string",
    )

    def _add_scan_config_args(p: argparse.ArgumentParser) -> None:
        """Add scan configuration arguments to a subparser."""
        p.add_argument(
            "--color", type=str, default="auto",
            choices=["auto", "color", "gray", "bw"],
            help="Color mode (default: auto)",
        )
        p.add_argument(
            "--quality", type=str, default="auto",
            choices=["auto", "normal", "fine", "superfine"],
            help="Scan quality (default: auto)",
        )
        p.add_argument(
            "--simplex", action="store_true", help="Single-sided scan",
        )
        p.add_argument(
            "--bleed-through", action="store_true", default=False,
            help="Enable bleed-through reduction (default: off)",
        )
        p.add_argument(
            "--paper-size", type=str, default="auto",
            choices=["auto", "a4", "a5", "business_card", "postcard"],
            help="Paper size (default: auto)",
        )
        p.add_argument(
            "--bw-density", type=int, default=0,
            help="B&W density 0-10 (default: 0, only for --color bw)",
        )
        p.add_argument(
            "--multi-feed", action="store_true", default=True,
            help="Enable multi-feed detection (default: on)",
        )
        p.add_argument(
            "--no-multi-feed", dest="multi_feed", action="store_false",
            help="Disable multi-feed detection",
        )
        p.add_argument(
            "--blank-page-removal", action="store_true", default=True,
            help="Enable blank page removal (default: on)",
        )
        p.add_argument(
            "--no-blank-page-removal", dest="blank_page_removal",
            action="store_false",
            help="Disable blank page removal",
        )

    scan_p = sub.add_parser("scan", help="Scan documents")
    scan_p.add_argument(
        "-o", "--output", type=str, default=None, help="Output directory",
    )
    _add_scan_config_args(scan_p)
    scan_p.add_argument(
        "--wait-button", action="store_true",
        help="Wait for physical button press before scanning",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.command == "discover":
        asyncio.run(cmd_discover(args))
    elif args.command == "pair":
        asyncio.run(cmd_pair(args))
    elif args.command == "scan":
        asyncio.run(cmd_scan(args))


if __name__ == "__main__":
    main()
