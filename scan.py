#!/usr/bin/env python3
"""ScanSnap CLI — discover and scan from the command line."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from scansnap.scanner import Scanner
from scansnap.discovery import ScanSnapDiscovery
from scansnap.packets import ScanConfig


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
        resolution=args.dpi,
        duplex=not args.simplex,
        color=True,
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

    scan_p = sub.add_parser("scan", help="Scan documents")
    scan_p.add_argument(
        "-o", "--output", type=str, default=None, help="Output directory",
    )
    scan_p.add_argument(
        "--dpi", type=int, default=300, help="Scan resolution (default: 300)",
    )
    scan_p.add_argument(
        "--simplex", action="store_true", help="Single-sided scan",
    )
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
    elif args.command == "scan":
        asyncio.run(cmd_scan(args))


if __name__ == "__main__":
    main()
