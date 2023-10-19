#!/usr/bin/python3

import argparse
import json
from typing import TextIO


def convert(ts_json: TextIO, ts_text: TextIO) -> None:
    """Convert trusted setup to text format."""
    trusted_setup = json.load(ts_json)
    g1_values = trusted_setup["g1_lagrange"]
    g2_values = trusted_setup["g2_monomial"]

    print(len(g1_values), file=ts_text)
    print(len(g2_values), file=ts_text)
    for g1 in g1_values:
        print(g1.replace("0x", ""), file=ts_text)
    for g2 in g2_values:
        print(g2.replace("0x", ""), file=ts_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert trusted setup from JSON to text format.",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=argparse.FileType("r"),
        help="the trusted setup in JSON format",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=argparse.FileType("w"),
        help="the trusted setup in text format",
    )
    args = parser.parse_args()

    try:
        convert(args.input, args.output)
    finally:
        args.input.close()
        args.output.close()
