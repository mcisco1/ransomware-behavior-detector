> **Python 3.11+ required.** Run `pip install -r requirements.txt` then `python setup_sandbox.py` to get started.


# Ransomware Behavior Simulator & Detector

A two-part offensive/defensive security project that demonstrates real-world ransomware behavioral analysis, detection, and automated incident response — built entirely in Python with a real-time web dashboard.

**Part A** is a safe ransomware simulator that targets an isolated sandbox directory — renaming files with `.encrypted` extensions, writing ransom notes, spiking file I/O, and injecting high-entropy data — reproducing the behavioral fingerprint of real ransomware families without doing anything destructive outside the sandbox. Includes a stealth/evasion mode that uses moderate entropy corruption and innocuous file extensions to test detector resilience.

**Part B** is a detection engine running as a daemon that monitors filesystem events in real time using `watchdog`, applies behavioral heuristics (rapid rename detection, Shannon entropy analysis, ransom note content scanning, YARA rule matching, abnormal write volume tracking), computes a bounded threat score using a windowed scoring model, identifies and kills the offending process via `psutil`, generates a structured JSON incident report, and rolls back all changes from a pre-attack shadow copy. A live web dashboard shows the detection timeline, captured process tree, threat score, and kill decisions as they happen.



# TESTS/SCREENSHOTS of the project working in real time. Only for demonstration purposes


TEST 1: CLEAN SANDBOX.

<img width="977" height="508" alt="cleansandbox" src="https://github.com/user-attachments/assets/0bbea02b-eae5-4735-856c-8938c8ef9fa4" />


Sandbox directory containing 14 target files before the attack. Files represent common document types — spreadsheets, configs, source code, PDFs.
---

## Architecture

```
┌────────────────────────────────┐     ┌──────────────────────────────────┐
│  PART A — SIMULATOR            │     │  PART B — DETECTION ENGINE       │
│                                │     │                                  │
│  ransomware_sim.py             │     │  watcher.py  (watchdog observer) │
│    ├─ spike I/O writes         │────▶│    ├─ filesystem event capture   │
│    ├─ inject high-entropy data │     │    ├─ ransom note content scan   │
│    ├─ rename *.encrypted       │     │    └─ routes to analyzer         │
│    └─ drop ransom notes        │     │                                  │
│                                │     │  analyzer.py (behavioral engine) │
│  payloads.py                   │     │    ├─ rename rate sliding window │
│    ├─ entropy generation       │     │    ├─ write volume tracking      │
│    ├─ moderate entropy (XOR)   │     │    ├─ Shannon entropy comparison │
│    └─ ransom note templates    │     │    ├─ ransom note keyword scan   │
│                                │     │    ├─ YARA rule matching         │
│  Stealth mode:                 │     │    └─ bounded windowed scoring   │
│    ├─ moderate entropy         │     │                                  │
│    ├─ innocuous extensions     │     │  response.py (incident response) │
│    └─ no ransom notes          │     │    ├─ process identification     │
│                                │     │    ├─ process tree capture       │
└────────────────────────────────┘     │    ├─ kill + child termination   │
                                       │    ├─ rollback from shadow copy  │
┌────────────────────────────────┐     │    └─ JSON incident report       │
│  SHADOW COPY                   │     │                                  │
│  shadow.py                     │     │  yara_scanner.py (optional)      │
│    ├─ pre-attack snapshot      │     │    └─ YARA rule-based detection  │
│    ├─ SHA-256 manifest         │     │                                  │
│    └─ integrity verification   │     │  reporter.py                     │
└────────────────────────────────┘     │    └─ structured incident reports│
                                       │                                  │
                                       │  dashboard/server.py (Flask+SSE) │
                                       │    └─ real-time web dashboard    │
                                       └──────────────────────────────────┘
```

## Detection Model

Each signal type contributes its weight **at most once** per detection window. Scores are computed on-demand from timestamped event deques — no accumulation, no unbounded growth.

| Signal                | Method                                              | Weight |
|-----------------------|-----------------------------------------------------|--------|
| Encrypted extension   | File renamed to `*.encrypted`                       | 15     |
| Rapid rename rate     | Sliding window rename rate exceeds threshold         | 25     |
| Abnormal write volume | Write events/sec above threshold                     | 20     |
| Entropy spike         | Shannon entropy jump > 2.0 bits/byte vs baseline     | 20     |
| Ransom note content   | Keyword matching (bitcoin, decrypt, wallet, etc.)     | 30     |
| YARA match            | Rule-based pattern matching on file content           | 30     |
| **Max possible**      |                                                       | **140**|

Response triggers at **50** (configurable). The bounded model prevents false escalation from repeated events of the same type.

## Setup

```bash
cd ransomware-sim-detector
pip install -r requirements.txt
python setup_sandbox.py
```

Optional — install YARA for rule-based detection (gracefully degrades if not available):
```bash
pip install yara-python
```

## Usage

**Terminal 1 — Start the detector (must start first):**
```bash
python run_detector.py
```
Opens the dashboard at `http://127.0.0.1:5000`.

**Terminal 2 — Launch the simulator:**
```bash
python run_simulator.py --speed fast
```

Speed options: `fast`, `normal`, `slow`.

Stealth mode (evades basic filename-based detection):
```bash
python run_simulator.py --speed fast --stealth
```

Use `--setup` flag to re-initialize the sandbox:
```bash
python run_simulator.py --speed fast --setup
```

### Docker

```bash
# Start detector only
docker compose up detector

# Start detector + simulator
docker compose --profile attack up
```

## What Happens

1. Detector validates configuration and initializes logging
2. Shadow copy takes a pre-attack snapshot of the sandbox with SHA-256 manifest
3. Analyzer builds an entropy baseline for all sandbox files
4. Simulator starts modifying files — writing high-entropy data, renaming with `.encrypted`, dropping ransom notes
5. Detector's watchdog observer catches every filesystem event in real time
6. Behavioral analyzer scores each event — entropy spikes, rename patterns, write volume, ransom note content, YARA matches
7. Each signal type contributes its weight at most once per window — score is bounded, not cumulative
8. Once threat score crosses threshold, response handler identifies the simulator process, captures its process tree, terminates it with child processes, waits for clean exit, and rolls back every change from the shadow copy
9. Reporter generates a structured JSON incident report with timeline, process tree, and kill decisions
10. Dashboard shows the full timeline, process tree, threat score, and kill decisions live via SSE

## Test Suite

50 tests covering the behavioral analyzer, shadow copy system, dashboard API, simulator payloads, and configuration validation.

```bash
python -m pytest tests/ -v
```

| Module          | Tests | Coverage                                               |
|-----------------|-------|--------------------------------------------------------|
| test_analyzer   | 15    | Shannon entropy, scoring, decay, spike, reset, summary |
| test_shadow     | 7     | Snapshot, rollback, integrity, full attack recovery     |
| test_dashboard  | 8     | All API routes, static assets, response structure       |
| test_simulator  | 11    | Payload generation, entropy levels, ransom notes        |
| test_config     | 9     | Validation rules, signal weights, edge cases            |

## Project Structure

```
ransomware-sim-detector/
├── config.py                Configuration, thresholds, signal weights, validation
├── utils.py                 Shared utilities (Shannon entropy, logging setup)
├── setup_sandbox.py         Sandbox initialization with sample files
├── run_simulator.py         Part A entry point (--speed, --stealth, --setup)
├── run_detector.py          Part B entry point with config validation
├── pytest.ini               Test configuration
├── requirements.txt         Python dependencies
├── Dockerfile               Container image (Python 3.11 + libyara)
├── docker-compose.yml       Multi-service orchestration
├── simulator/
│   ├── ransomware_sim.py    Simulator core (I/O spike, encrypt, stealth mode)
│   └── payloads.py          High/moderate entropy, ransom note templates
├── detector/
│   ├── daemon.py            Detection daemon orchestrator
│   ├── watcher.py           Watchdog filesystem observer + content scanning
│   ├── analyzer.py          Behavioral analysis (windowed bounded scoring)
│   ├── shadow.py            Shadow copy snapshot and rollback
│   ├── response.py          Process kill and incident response
│   ├── events.py            Thread-safe event store with pub/sub
│   ├── reporter.py          Structured JSON incident reports
│   └── yara_scanner.py      Optional YARA integration (graceful degradation)
├── rules/
│   └── ransom_note.yar      YARA rule for ransom note detection
├── dashboard/
│   ├── server.py            Flask + SSE backend with report API
│   ├── templates/
│   │   └── dashboard.html   Dashboard layout
│   └── static/
│       ├── style.css        Dark theme styling
│       └── main.js          Real-time frontend (XSS-safe, SSE reconnection)
└── tests/
    ├── conftest.py          Shared fixtures and test configuration
    ├── test_analyzer.py     Behavioral analyzer tests
    ├── test_shadow.py       Shadow copy and rollback tests
    ├── test_dashboard.py    Dashboard API route tests
    ├── test_simulator.py    Payload generation tests
    └── test_config.py       Configuration validation tests
```

## Technologies

- **Python 3.8+** — core runtime
- **watchdog** — cross-platform filesystem event monitoring
- **psutil** — process identification, tree enumeration, termination
- **Flask** — dashboard web server with Server-Sent Events
- **Chart.js** — stacked bar detection timeline visualization
- **Shannon entropy** — statistical analysis of file content randomness
- **YARA** — optional rule-based pattern matching (graceful degradation)
- **pytest** — test framework with fixtures and parameterized tests
- **Docker** — containerized deployment with compose profiles

## Key Concepts Demonstrated

- Ransomware behavioral signatures and kill chain modeling
- Bounded windowed threat scoring (per-signal-type deques, not cumulative)
- Real-time filesystem monitoring and event-driven detection
- Sliding window rate analysis for anomaly detection
- Shannon entropy as a cryptographic activity indicator
- Ransom note content analysis (keyword matching + YARA rules)
- Stealth/evasion simulation (moderate entropy, innocuous extensions)
- Automated incident response with process tree capture
- Shadow copy integrity verification using SHA-256 manifests
- Structured JSON incident reporting
- Full-stack security dashboard with live SSE event streaming
- XSS-safe DOM rendering and SSE reconnection handling
- Comprehensive test coverage across all subsystems
