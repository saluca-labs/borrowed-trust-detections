"""Compile-check the YARA pack and smoke-test it against known-benign binaries.

Usage: python validate.py
Requires: pip install yara-python
"""
import os
import sys

import yara

RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "borrowed-trust.yar")

BENIGN = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\curl.exe",
    r"C:\Windows\System32\msvcp_win.dll",
    r"C:\Windows\System32\kernel32.dll",
]


def main() -> int:
    try:
        rules = yara.compile(filepath=RULES)
    except yara.SyntaxError as exc:
        print("COMPILE FAILED:", exc)
        return 1

    names = [r.identifier for r in rules]
    print("COMPILE OK - {} rules".format(len(names)))
    for n in names:
        print("   ", n)

    print("\nFalse-positive smoke test against known-benign system binaries:")
    fps = 0
    for path in BENIGN:
        if not os.path.exists(path):
            print("  skip (absent): {}".format(path))
            continue
        hits = [m.rule for m in rules.match(path)]
        if hits:
            fps += 1
            print("  FP  {} -> {}".format(path, hits))
        else:
            print("  ok  {}".format(path))

    print("\n{} false positive(s) on the benign set.".format(fps))
    return 1 if fps else 0


if __name__ == "__main__":
    sys.exit(main())
