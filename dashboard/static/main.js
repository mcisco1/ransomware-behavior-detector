(function () {
    "use strict";

    var events = [];
    var timelineChart = null;
    var sseSource = null;
    var sseReconnecting = false;
    var severityCounts = { info: 0, medium: 0, high: 0, critical: 0 };

    // --- DOM refs ---
    var scoreBar = document.getElementById("score-bar");
    var scoreValue = document.getElementById("score-value");
    var scoreThreshold = document.getElementById("score-threshold");
    var renameRate = document.getElementById("rename-rate");
    var writeRate = document.getElementById("write-rate");
    var reasonsList = document.getElementById("reasons-list");
    var statTotal = document.getElementById("stat-total");
    var statCritical = document.getElementById("stat-critical");
    var statHigh = document.getElementById("stat-high");
    var statMedium = document.getElementById("stat-medium");
    var processTree = document.getElementById("process-tree");
    var killLog = document.getElementById("kill-log");
    var eventLog = document.getElementById("event-log");
    var logCount = document.getElementById("log-count");
    var statusDot = document.getElementById("status-dot");
    var statusText = document.getElementById("status-text");

    // --- INIT ---
    function init() {
        initTimeline();
        loadInitialData();
        connectSSE();
        pollThreat();
    }

    // --- TIMELINE CHART ---
    function initTimeline() {
        var ctx = document.getElementById("timeline-chart").getContext("2d");
        timelineChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: [],
                datasets: [
                    { label: "Critical", data: [], backgroundColor: "#ff3355", stack: "s" },
                    { label: "High", data: [], backgroundColor: "#ffab00", stack: "s" },
                    { label: "Medium", data: [], backgroundColor: "#448aff", stack: "s" },
                    { label: "Info", data: [], backgroundColor: "#3a3a55", stack: "s" }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: "#1a1a2e" },
                        ticks: { color: "#6a6a88", font: { size: 10, family: "Consolas, monospace" }, maxRotation: 0 }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: "#1a1a2e" },
                        ticks: { color: "#6a6a88", font: { size: 10, family: "Consolas, monospace" }, stepSize: 1 }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: "#6a6a88", font: { size: 10, family: "Consolas, monospace" }, boxWidth: 12 }
                    }
                }
            }
        });
    }

    function rebuildTimeline() {
        if (!events.length) return;

        var buckets = {};
        events.forEach(function (ev) {
            var d = new Date(ev.timestamp);
            var key = d.getHours().toString().padStart(2, "0") + ":" +
                      d.getMinutes().toString().padStart(2, "0") + ":" +
                      (Math.floor(d.getSeconds() / 5) * 5).toString().padStart(2, "0");
            if (!buckets[key]) buckets[key] = { critical: 0, high: 0, medium: 0, info: 0 };
            var sev = ev.severity || "info";
            if (buckets[key][sev] !== undefined) buckets[key][sev]++;
        });

        var keys = Object.keys(buckets).sort();
        var last30 = keys.slice(-30);

        timelineChart.data.labels = last30;
        timelineChart.data.datasets[0].data = last30.map(function (k) { return buckets[k].critical; });
        timelineChart.data.datasets[1].data = last30.map(function (k) { return buckets[k].high; });
        timelineChart.data.datasets[2].data = last30.map(function (k) { return buckets[k].medium; });
        timelineChart.data.datasets[3].data = last30.map(function (k) { return buckets[k].info; });
        timelineChart.update();
    }

    // --- INITIAL DATA LOAD ---
    function loadInitialData() {
        fetch("/api/events")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                events = data.events || [];
                updateEventLog(events);
                rebuildTimeline();
                updateCounts();

                if (data.kill_decisions && data.kill_decisions.length) {
                    data.kill_decisions.forEach(renderKillDecision);
                }
                if (data.process_tree && data.process_tree.pid) {
                    renderProcessTree(data.process_tree);
                }

                setStatus("active", "MONITORING");
            })
            .catch(function () {
                setStatus("", "OFFLINE");
            });
    }

    // --- SSE ---
    function connectSSE() {
        if (sseReconnecting) return;
        if (sseSource) sseSource.close();

        sseSource = new EventSource("/api/stream");

        sseSource.onmessage = function (msg) {
            try {
                var ev = JSON.parse(msg.data);
                events.push(ev);
                appendLogEntry(ev);
                countEvent(ev);
                rebuildTimeline();

                if (ev.type === "KILL_DECISION") {
                    renderKillDecision(ev.metadata || {});
                }
                if (ev.type === "THREAT_CONFIRMED" || ev.type === "RESPONSE_INITIATED") {
                    setStatus("alert", "THREAT DETECTED");
                }
                if (ev.type === "RESPONSE_COMPLETE") {
                    setStatus("active", "RESOLVED");
                }
            } catch (e) { /* skip malformed */ }
        };

        sseSource.onerror = function () {
            if (sseReconnecting) return;
            sseReconnecting = true;
            setStatus("", "RECONNECTING");
            setTimeout(function () {
                sseReconnecting = false;
                connectSSE();
            }, 3000);
        };
    }

    // --- THREAT POLLING ---
    function pollThreat() {
        setInterval(function () {
            fetch("/api/threat")
                .then(function (r) { return r.json(); })
                .then(function (t) {
                    updateThreatScore(t);
                })
                .catch(function () {});
        }, 1000);
    }

    function updateThreatScore(t) {
        var score = t.score || 0;
        var threshold = t.threshold || 50;
        var maxPossible = t.max_possible || (threshold * 2);
        var pct = Math.min((score / maxPossible) * 100, 100);

        scoreValue.textContent = score;
        scoreThreshold.textContent = "/ " + threshold + " threshold (max " + maxPossible + ")";
        scoreBar.style.width = pct + "%";

        scoreBar.className = "score-bar-fill";
        scoreValue.className = "score-number";

        if (score >= threshold) {
            scoreBar.classList.add("danger");
            scoreValue.classList.add("danger");
        } else if (score >= threshold * 0.6) {
            scoreBar.classList.add("warn");
            scoreValue.classList.add("warn");
        }

        renameRate.textContent = (t.rename_rate || 0).toFixed(1) + "/s";
        writeRate.textContent = (t.write_rate || 0).toFixed(1) + "/s";

        reasonsList.innerHTML = "";
        if (t.reasons && t.reasons.length) {
            t.reasons.forEach(function (r) {
                var div = document.createElement("div");
                div.className = "reason-item";
                div.textContent = r;
                reasonsList.appendChild(div);
            });
        } else {
            reasonsList.innerHTML = '<div class="empty-state">No detections yet</div>';
        }
    }

    // --- EVENT LOG ---
    function updateEventLog(evts) {
        eventLog.innerHTML = "";
        severityCounts = { info: 0, medium: 0, high: 0, critical: 0 };
        evts.forEach(function (ev) {
            appendLogEntry(ev);
            countEvent(ev);
        });
    }

    function appendLogEntry(ev) {
        var row = document.createElement("div");
        row.className = "log-entry";

        var ts = new Date(ev.timestamp);
        var time = ts.getHours().toString().padStart(2, "0") + ":" +
                   ts.getMinutes().toString().padStart(2, "0") + ":" +
                   ts.getSeconds().toString().padStart(2, "0");

        var sevSpan = document.createElement("span");
        sevSpan.className = "log-severity " + (ev.severity || "info");
        sevSpan.textContent = ev.severity || "info";

        var typeSpan = document.createElement("span");
        typeSpan.className = "log-type";
        typeSpan.textContent = ev.type || "";

        var timeSpan = document.createElement("span");
        timeSpan.className = "log-time";
        timeSpan.textContent = time;

        var descSpan = document.createElement("span");
        descSpan.className = "log-desc";
        descSpan.textContent = ev.description || "";

        row.appendChild(timeSpan);
        row.appendChild(sevSpan);
        row.appendChild(typeSpan);
        row.appendChild(descSpan);

        eventLog.appendChild(row);
        eventLog.scrollTop = eventLog.scrollHeight;
        logCount.textContent = events.length + " events";
    }

    function countEvent(ev) {
        var s = ev.severity || "info";
        if (severityCounts[s] !== undefined) severityCounts[s]++;
        statTotal.textContent = events.length;
        statCritical.textContent = severityCounts.critical;
        statHigh.textContent = severityCounts.high;
        statMedium.textContent = severityCounts.medium;
    }

    function updateCounts() {
        statTotal.textContent = events.length;
        statCritical.textContent = severityCounts.critical;
        statHigh.textContent = severityCounts.high;
        statMedium.textContent = severityCounts.medium;
    }

    // --- PROCESS TREE ---
    function renderProcessTree(tree) {
        if (!tree || !tree.pid) return;

        var html = '<div class="proc-node">';

        if (tree.parent) {
            html += '<div class="proc-parent-label">PARENT PROCESS</div>';
            html += '<div class="proc-child">' + escapeHtml(tree.parent.name) + ' (PID ' + tree.parent.pid + ')</div>';
            html += '<div style="margin:8px 0;color:var(--text-dim);">&darr;</div>';
        }

        html += '<div class="proc-main killed">';
        html += '<div class="proc-field"><span class="proc-key">PID</span><span class="proc-val pid">' + tree.pid + '</span></div>';
        html += '<div class="proc-field"><span class="proc-key">Name</span><span class="proc-val">' + escapeHtml(tree.name || "") + '</span></div>';
        html += '<div class="proc-field"><span class="proc-key">Status</span><span class="proc-val">' + escapeHtml(tree.status || "") + '</span></div>';

        if (tree.cpu_percent !== undefined && tree.cpu_percent !== null) {
            html += '<div class="proc-field"><span class="proc-key">CPU</span><span class="proc-val">' + Number(tree.cpu_percent).toFixed(1) + '%</span></div>';
        }
        if (tree.memory_mb !== undefined) {
            html += '<div class="proc-field"><span class="proc-key">Memory</span><span class="proc-val">' + tree.memory_mb + ' MB</span></div>';
        }
        if (tree.cmdline) {
            html += '<div class="proc-field"><span class="proc-key">Cmd</span><span class="proc-val" style="font-size:10px;word-break:break-all;">' + escapeHtml(tree.cmdline) + '</span></div>';
        }
        if (tree.create_time) {
            var ct = new Date(tree.create_time);
            html += '<div class="proc-field"><span class="proc-key">Started</span><span class="proc-val">' + ct.toLocaleTimeString() + '</span></div>';
        }

        html += '</div>';

        if (tree.children && tree.children.length) {
            html += '<div class="proc-children">';
            tree.children.forEach(function (ch) {
                html += '<div class="proc-child">' + escapeHtml(ch.name) + ' (PID ' + ch.pid + ') — ' + escapeHtml(ch.status || "") + '</div>';
            });
            html += '</div>';
        }

        html += '</div>';
        processTree.innerHTML = html;
    }

    // --- KILL DECISIONS ---
    function renderKillDecision(decision) {
        if (!decision.pid && decision.pid !== 0) return;

        var existing = killLog.querySelector(".empty-state");
        if (existing) existing.remove();

        var div = document.createElement("div");
        div.className = "kill-entry";

        var ts = decision.timestamp ? new Date(decision.timestamp).toLocaleTimeString() : "";
        var actionClass = (decision.action || "").indexOf("terminated") >= 0 ? "terminated" : "failed";

        div.innerHTML =
            '<div class="kill-header">' +
                '<span class="kill-pid">PID ' + decision.pid + ' — ' + escapeHtml(decision.process_name || "") + '</span>' +
                '<span class="kill-time">' + escapeHtml(ts) + '</span>' +
            '</div>' +
            '<span class="kill-action ' + escapeHtml(actionClass) + '">' + escapeHtml(decision.action || "") + '</span>' +
            '<div class="kill-reason">' + escapeHtml(decision.reason || "") + '</div>';

        killLog.appendChild(div);

        fetch("/api/events")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.process_tree && data.process_tree.pid) {
                    renderProcessTree(data.process_tree);
                }
            })
            .catch(function () {});
    }

    // --- STATUS ---
    function setStatus(mode, text) {
        statusText.textContent = text;
        statusDot.className = "status-dot";
        if (mode === "active") statusDot.classList.add("active");
        if (mode === "alert") statusDot.classList.add("alert");
    }

    // --- UTIL ---
    function escapeHtml(str) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // --- START ---
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
