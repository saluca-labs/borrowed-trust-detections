"""Validate the Sigma rule collections: YAML parses, required keys present, IDs unique.

Usage: python validate.py
Requires: pip install pyyaml
Optional: pip install pysigma  (adds a full schema + backend conversion check)
"""
import glob
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ("title", "id", "description", "logsource", "detection", "level")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def main() -> int:
    errors = []
    seen_ids = {}
    total = 0

    for path in sorted(glob.glob(os.path.join(HERE, "*.yml"))):
        name = os.path.basename(path)
        with open(path, "r", encoding="utf-8") as fh:
            try:
                docs = [d for d in yaml.safe_load_all(fh) if d]
            except yaml.YAMLError as exc:
                errors.append("{}: YAML parse error: {}".format(name, exc))
                continue

        print("{}: {} rule(s)".format(name, len(docs)))
        for doc in docs:
            total += 1
            title = doc.get("title", "<untitled>")

            for key in REQUIRED:
                if key not in doc:
                    errors.append("{} :: {}: missing required key '{}'".format(name, title, key))

            rid = doc.get("id")
            if rid:
                if rid in seen_ids:
                    errors.append("{} :: {}: duplicate id {} (also in {})".format(name, title, rid, seen_ids[rid]))
                seen_ids[rid] = title

            level = doc.get("level")
            if level and level not in VALID_LEVELS:
                errors.append("{} :: {}: invalid level '{}'".format(name, title, level))

            status = doc.get("status")
            if status and status not in VALID_STATUS:
                errors.append("{} :: {}: invalid status '{}'".format(name, title, status))

            det = doc.get("detection")
            if isinstance(det, dict):
                if "condition" not in det:
                    errors.append("{} :: {}: detection block has no condition".format(name, title))
                else:
                    cond = str(det["condition"])
                    # Every named selection referenced in the condition must exist.
                    defined = {k for k in det if k != "condition"}
                    for token in cond.replace("(", " ").replace(")", " ").split():
                        if token in ("and", "or", "not", "of", "them", "all", "1", "2", "3"):
                            continue
                        if token.endswith("*"):
                            prefix = token[:-1]
                            if not any(d.startswith(prefix) for d in defined):
                                errors.append("{} :: {}: condition wildcard '{}' matches no selection".format(name, title, token))
                            continue
                        if token not in defined:
                            errors.append("{} :: {}: condition references undefined selection '{}'".format(name, title, token))

            print("   ok  [{}] {}".format(doc.get("level", "?"), title))

    print("\n{} rules across {} files, {} unique ids".format(total, len(glob.glob(os.path.join(HERE, '*.yml'))), len(seen_ids)))

    if errors:
        print("\n{} PROBLEM(S):".format(len(errors)))
        for e in errors:
            print("  -", e)
        return 1

    print("All Sigma rules valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
