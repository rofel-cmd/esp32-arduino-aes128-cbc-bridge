#!/usr/bin/env python3
"""Recompute the public timing summary from the sanitized evidence record."""
from __future__ import annotations

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    record = json.loads((ROOT / "september-14-six-command.json").read_text(encoding="utf-8"))
    commands = record["commands"]
    rtt = [row["rtt_ms"] for row in commands]
    enc = [row["encryption_us_per_byte"] for row in commands]
    dec = [row["decryption_us_per_byte"] for row in commands]
    result = {
        "matches": len(commands),
        "rtt_mean_ms": statistics.mean(rtt),
        "rtt_sample_sd_ms": statistics.stdev(rtt),
        "rtt_range_ms": [min(rtt), max(rtt)],
        "encryption_mean_us_per_byte": statistics.mean(enc),
        "decryption_mean_us_per_byte": statistics.mean(dec),
        "decryption_sample_sd_us_per_byte": statistics.stdev(dec),
        "derived_32_byte_decryption_ms": statistics.mean(dec) * 32 / 1000,
    }
    expected = {
        "matches": 6,
        "rtt_mean_ms": 143.16666666666666,
        "rtt_sample_sd_ms": 12.937026963976951,
        "rtt_range_ms": [130, 168],
        "encryption_mean_us_per_byte": 0.8966666666666666,
        "decryption_mean_us_per_byte": 74.29,
        "decryption_sample_sd_us_per_byte": 0.061967733539321015,
        "derived_32_byte_decryption_ms": 2.37728,
    }
    for key, wanted in expected.items():
        actual = result[key]
        if isinstance(wanted, float):
            assert abs(actual - wanted) < 1e-12, (key, actual, wanted)
        else:
            assert actual == wanted, (key, actual, wanted)
    print(json.dumps(result, indent=2))
    print("EVIDENCE RESULTS OK")


if __name__ == "__main__":
    main()
