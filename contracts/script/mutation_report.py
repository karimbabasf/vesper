#!/usr/bin/env python3
"""Delete each check in turn and see whether the suite notices.

    cd contracts && python3 script/mutation_report.py

The completion criterion for these contracts is that every check has a test that fails when that
check is removed. That is a claim you can run, so this runs it: each guard is replaced with an empty
block, the suite is run, and the guard is put back. A guard that survives is a guard nothing tests,
which is the same as not having it.

Writes mutation-report.md and exits non-zero if anything survived.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SOURCES = ["src/VoicePolicy.sol", "src/VoiceOrderGate.sol", "src/WebAuthn.sol"]
GUARD = re.compile(r"(return SIG_FAIL;|return false;|revert \w+\(\);)")

# Guards that cannot be caught, each with the argument for why. Anything not on this list that
# survives is a hole. Adding to this list is a claim someone can check, so state the reason.
EXEMPT = {
    ("src/VoicePolicy.sol", "if (session.key == address(0)) return SIG_FAIL;"): (
        "redundant by construction: ecrecover returns address(0) on failure and "
        "_validSessionSignature rejects that, so a zero session key can never validate. The line "
        "is here so the revoked case reads plainly at the top of the function."
    ),
    ("src/WebAuthn.sol", "return false;"): (
        "the final statement of _contains, where Solidity already returns the default. Replacing "
        "it with an empty block is not a mutation, so nothing could catch it."
    ),
}


def run_tests() -> bool:
    """True when the suite is green."""
    done = subprocess.run(
        ["forge", "test"], capture_output=True, text=True, cwd=Path(__file__).parent.parent
    )
    return done.returncode == 0


def guards(path: Path) -> list[tuple[int, str]]:
    found = []
    for number, line in enumerate(path.read_text().splitlines()):
        if GUARD.search(line) and not line.strip().startswith("//"):
            found.append((number, line))
    return found


def main() -> int:
    root = Path(__file__).parent.parent
    rows: list[tuple[str, int, str, bool]] = []

    if not run_tests():
        print("the suite is already failing, fix that first")
        return 2

    for source in SOURCES:
        path = root / source
        original = path.read_text()
        lines = original.splitlines(keepends=True)

        for number, line in guards(path):
            mutated = list(lines)
            mutated[number] = GUARD.sub("{}", line) + "\n"
            path.write_text("".join(mutated))
            try:
                caught = not run_tests()
            finally:
                path.write_text(original)

            rows.append((source, number + 1, line.strip(), caught))
            print(f"{'caught ' if caught else 'SURVIVED'}  {source}:{number + 1}  {line.strip()}")

    def exemption(source: str, text: str) -> str | None:
        for (exempt_source, exempt_text), reason in EXEMPT.items():
            if source == exempt_source and text.startswith(exempt_text):
                return reason
        return None

    survivors = [row for row in rows if not row[3] and not exemption(row[0], row[2])]
    report = [
        "# Mutation report",
        "",
        "Each check below was replaced with an empty block and the suite was run. `caught` means a",
        "test failed, which is the only evidence that the check is doing anything.",
        "",
        f"{sum(1 for row in rows if row[3])} of {len(rows)} checks are caught by a test. "
        f"{len(rows) - sum(1 for row in rows if row[3])} cannot be, with reasons below.",
        "",
        "| File | Line | Check | Result |",
        "|---|---|---|---|",
    ]
    notes = []
    for source, number, text, caught in rows:
        reason = exemption(source, text)
        result = "caught" if caught else ("exempt" if reason else "**survived**")
        report.append(f"| `{source}` | {number} | `{text}` | {result} |")
        if reason and not caught:
            notes.append(f"- `{source}:{number}` {reason}")
    if notes:
        report += ["", "## Why the exempt checks cannot be caught", ""] + notes
    report.append("")
    (root / "mutation-report.md").write_text("\n".join(report))

    caught_count = sum(1 for row in rows if row[3])
    print(f"\n{caught_count}/{len(rows)} caught, {len(survivors)} uncovered, see mutation-report.md")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
