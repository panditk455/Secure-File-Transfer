#!/usr/bin/env python3
"""Run every SiFT attack demonstration and print a summary.

    python attacks/run_all.py

Exit code is 0 only if every defence held. Useful as a living, runnable proof
that the threat model's claims are actually enforced by the code.
"""

import importlib
import sys

from _harness import BOLD, GREEN, RED, RESET

ATTACKS = [
    ("attack_tamper", "Ciphertext tampering"),
    ("attack_replay", "Message replay"),
    ("attack_downgrade", "Protocol downgrade / header tampering"),
    ("attack_traversal", "Path traversal (authenticated user)"),
    ("attack_nonce_reuse", "Nonce reuse (single-key vs directional keys)"),
]


def main() -> int:
    results = []
    for module_name, title in ATTACKS:
        module = importlib.import_module(module_name)
        try:
            held = bool(module.run())
        except Exception as e:  # noqa: BLE001
            print(f"  {RED}[ERROR]{RESET} {module_name}: {e!r}")
            held = False
        results.append((title, held))

    print(f"\n{BOLD}==================== SUMMARY ===================={RESET}")
    all_held = True
    for title, held in results:
        tag = f"{GREEN}DEFENCE HELD{RESET}" if held else f"{RED}FAILED{RESET}"
        print(f"  [{tag}] {title}")
        all_held = all_held and held
    print(f"{BOLD}================================================{RESET}")
    return 0 if all_held else 1


if __name__ == "__main__":
    sys.exit(main())
