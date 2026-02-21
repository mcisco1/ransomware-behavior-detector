import sys
import signal

import config
from utils import setup_logging
from detector.daemon import DetectionDaemon
from dashboard.server import create_app


def main():
    config.validate_config()
    setup_logging(config.LOG_DIR)

    daemon = DetectionDaemon()

    if not daemon.start():
        print("[DETECTOR] Failed to start. Is the sandbox initialized?")
        print("[DETECTOR] Run: python setup_sandbox.py")
        sys.exit(1)

    print(f"[DETECTOR] Monitoring: {config.SANDBOX_DIR}")
    print(f"[DETECTOR] Dashboard:  http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    print("[DETECTOR] Press Ctrl+C to stop.\n")

    app = create_app(daemon)

    def shutdown(signum, frame):
        print("\n[DETECTOR] Shutting down...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (OSError, ValueError):
        pass

    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
