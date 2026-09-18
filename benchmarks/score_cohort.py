"""Host-side benchmark grader; never mount expected values into the agent sandbox."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.detection.scoring import aggregate_cohort, grade_run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    grade = commands.add_parser("grade", help="Grade one completed run")
    grade.add_argument("--record", type=Path, required=True)
    grade.add_argument("--expected-file", type=Path, required=True)
    grade.add_argument("--output-file", type=Path, required=True)
    grade.add_argument("--secure-control", action="store_true")
    aggregate = commands.add_parser("aggregate", help="Aggregate graded run records")
    aggregate.add_argument("records", type=Path, nargs="+")
    aggregate.add_argument("--write", type=Path)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "grade":
        result = grade_run(
            args.record,
            expected_value=args.expected_file.read_text(encoding="utf-8").strip(),
            collected_output=args.output_file.read_text(encoding="utf-8"),
            secure_control=args.secure_control,
        )
    else:
        result = aggregate_cohort(args.records)
        if args.write is not None:
            args.write.write_text(
                json.dumps(result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
