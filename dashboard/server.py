import os
import json
import queue
import threading

from flask import Flask, render_template, jsonify, Response, send_from_directory


def create_app(daemon):
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )

    sse_clients = []
    sse_lock = threading.Lock()

    def broadcast_event(event):
        data = json.dumps(event.to_dict())
        dead_clients = []
        with sse_lock:
            for client_q in sse_clients:
                try:
                    client_q.put_nowait(data)
                except queue.Full:
                    dead_clients.append(client_q)
            for q in dead_clients:
                sse_clients.remove(q)

    daemon.event_store.subscribe(broadcast_event)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/events")
    def api_all_events():
        return jsonify(daemon.event_store.get_all())

    @app.route("/api/events/recent")
    def api_recent_events():
        return jsonify(daemon.event_store.get_recent(200))

    @app.route("/api/threat")
    def api_threat():
        return jsonify(daemon.analyzer.get_threat_summary())

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "running": daemon.is_running(),
        })

    @app.route("/api/reports")
    def api_reports():
        report_dir = app.config.get("REPORT_DIR") or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "reports"
        )
        if not os.path.isdir(report_dir):
            return jsonify([])
        files = sorted(
            [f for f in os.listdir(report_dir) if f.endswith(".json")],
            reverse=True,
        )
        return jsonify(files)

    @app.route("/api/reports/<filename>")
    def api_report_detail(filename):
        report_dir = app.config.get("REPORT_DIR") or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "reports"
        )
        if not filename.endswith(".json"):
            return jsonify({"error": "invalid filename"}), 400
        return send_from_directory(report_dir, filename)

    @app.route("/api/stream")
    def event_stream():
        client_q = queue.Queue(maxsize=500)
        with sse_lock:
            sse_clients.append(client_q)

        def generate():
            try:
                while True:
                    try:
                        data = client_q.get(timeout=25)
                        yield f"data: {data}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                with sse_lock:
                    if client_q in sse_clients:
                        sse_clients.remove(client_q)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return app
