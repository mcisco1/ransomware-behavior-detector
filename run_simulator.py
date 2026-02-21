import os
import argparse

import config
from setup_sandbox import create_sandbox
from simulator.ransomware_sim import RansomwareSimulator


def main():
    parser = argparse.ArgumentParser(description="Ransomware Behavior Simulator")
    parser.add_argument(
        "--speed",
        choices=["fast", "normal", "slow"],
        default="normal",
        help="Simulation speed (affects delay between file operations)",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Re-initialize sandbox before running",
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Evasion mode: moderate entropy, innocuous extensions, no ransom notes",
    )
    args = parser.parse_args()

    if args.setup or not os.path.exists(config.SANDBOX_DIR):
        create_sandbox()

    sim = RansomwareSimulator(speed=args.speed, stealth=args.stealth)

    try:
        sim.run()
    except KeyboardInterrupt:
        print("\n[SIM] Interrupted.")
        sim.stop()


if __name__ == "__main__":
    main()
