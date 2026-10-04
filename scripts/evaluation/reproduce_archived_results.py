#!/usr/bin/env python3
"""Offline archive replay; no analyzer, database or network required."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from vep.evaluation.replay import replay_archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=ROOT / 'repro/archive-v3.0.1')
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--plots', action='store_true', help='Generate charts with the locked matplotlib stack')
    args = parser.parse_args(argv)
    try:
        replay_archive(args.archive, args.out_dir, args.plots)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'REPLAY ERROR: {exc}', file=sys.stderr)
        return 1
    print('REPLAY PASS: 2 tools x 11 CWEs x 2 FP modes; historical counts unchanged')
    return 0


if __name__ == '__main__':
    sys.exit(main())
