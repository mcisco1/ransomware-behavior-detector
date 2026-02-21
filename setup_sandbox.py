import os
import config


def create_sandbox():
    os.makedirs(config.SANDBOX_DIR, exist_ok=True)

    sample_files = {
        "report_q4.docx": (
            "Quarterly financial report with detailed analysis of revenue streams "
            "and operating expenses. Net income grew 12% year-over-year driven by "
            "expansion into new markets and improved operational efficiency across "
            "all business units. Gross margin held steady at 68% despite supply "
            "chain headwinds in Q3. Cash reserves remain strong at $4.2M."
        ),
        "employee_records.csv": (
            "name,department,salary,start_date\n"
            "John Smith,Engineering,95000,2021-03-15\n"
            "Jane Doe,Marketing,87000,2020-07-22\n"
            "Carlos Vega,Engineering,102000,2019-11-01\n"
            "Priya Patel,Finance,91000,2022-01-10\n"
            "Wei Chen,Engineering,98000,2020-09-18\n"
            "Maria Lopez,Operations,84000,2021-06-30\n"
            "David Kim,Marketing,79000,2023-02-14\n"
        ),
        "project_plan.pdf": (
            "Project timeline and milestones for the upcoming product launch. "
            "Phase 1: Requirements gathering (2 weeks). Phase 2: Design and "
            "prototyping (3 weeks). Phase 3: Development sprint 1-3 (6 weeks). "
            "Phase 4: QA and regression testing (2 weeks). Phase 5: Staged "
            "rollout with 10% canary deployment before full production push."
        ),
        "database_backup.sql": (
            "CREATE TABLE users (\n"
            "    id SERIAL PRIMARY KEY,\n"
            "    username VARCHAR(255) NOT NULL UNIQUE,\n"
            "    email VARCHAR(255) NOT NULL,\n"
            "    created_at TIMESTAMP DEFAULT NOW()\n"
            ");\n\n"
            "CREATE TABLE orders (\n"
            "    id SERIAL PRIMARY KEY,\n"
            "    user_id INTEGER REFERENCES users(id),\n"
            "    total DECIMAL(10,2) NOT NULL,\n"
            "    status VARCHAR(50) DEFAULT 'pending'\n"
            ");\n\n"
            "INSERT INTO users (username, email) VALUES\n"
            "('admin', 'admin@company.com'),\n"
            "('jsmith', 'jsmith@company.com');\n"
        ),
        "meeting_notes.txt": (
            "Weekly standup - 2024-10-14\n\n"
            "Attendees: full engineering team\n\n"
            "Updates:\n"
            "- Auth service migration to OAuth2 is 80% complete\n"
            "- Load testing revealed connection pool bottleneck at 500 rps\n"
            "- New monitoring dashboards deployed to staging\n\n"
            "Action items:\n"
            "- Carlos: finish token refresh flow by Wednesday\n"
            "- Priya: coordinate with DevOps on connection pool tuning\n"
            "- Wei: write runbook for the new alerting pipeline\n"
        ),
        "source_code.py": (
            "import hashlib\n"
            "import hmac\n"
            "from datetime import datetime, timedelta\n\n\n"
            "def generate_session_token(user_id, secret_key):\n"
            "    payload = f'{user_id}:{datetime.utcnow().isoformat()}'\n"
            "    signature = hmac.new(\n"
            "        secret_key.encode(), payload.encode(), hashlib.sha256\n"
            "    ).hexdigest()\n"
            "    return f'{payload}:{signature}'\n\n\n"
            "def validate_token(token, secret_key, max_age_hours=24):\n"
            "    parts = token.rsplit(':', 1)\n"
            "    if len(parts) != 2:\n"
            "        return False\n"
            "    payload, sig = parts\n"
            "    expected = hmac.new(\n"
            "        secret_key.encode(), payload.encode(), hashlib.sha256\n"
            "    ).hexdigest()\n"
            "    return hmac.compare_digest(sig, expected)\n"
        ),
        "budget_2024.xlsx": (
            "Department,Q1,Q2,Q3,Q4,Total\n"
            "Engineering,450000,475000,490000,510000,1925000\n"
            "Marketing,180000,210000,195000,220000,805000\n"
            "Operations,120000,125000,130000,135000,510000\n"
            "Finance,95000,98000,97000,100000,390000\n"
            "HR,75000,78000,76000,80000,309000\n"
        ),
        "client_contracts.pdf": (
            "SERVICE LEVEL AGREEMENT\n\n"
            "This agreement establishes the terms of service between Provider "
            "and Client for managed infrastructure services. Guaranteed uptime: "
            "99.95%. Response time for P1 incidents: 15 minutes. Monthly "
            "reporting on SLA compliance metrics. Penalty clause: 5% credit "
            "per 0.01% downtime below guaranteed threshold."
        ),
        "api_documentation.md": (
            "# Internal API Reference\n\n"
            "## Authentication\n"
            "All endpoints require Bearer token in Authorization header.\n\n"
            "## Endpoints\n\n"
            "### GET /api/v2/users\n"
            "Returns paginated user list. Query params: page, limit, sort.\n\n"
            "### POST /api/v2/users\n"
            "Create new user. Body: {username, email, role}\n\n"
            "### GET /api/v2/orders/:id\n"
            "Returns order details with line items and shipping status.\n"
        ),
        "server_config.yaml": (
            "server:\n"
            "  host: 0.0.0.0\n"
            "  port: 8080\n"
            "  workers: 4\n"
            "  timeout: 30\n"
            "  keepalive: 65\n\n"
            "database:\n"
            "  host: db.internal.corp\n"
            "  port: 5432\n"
            "  pool_size: 20\n"
            "  max_overflow: 10\n\n"
            "redis:\n"
            "  host: cache.internal.corp\n"
            "  port: 6379\n"
            "  db: 0\n"
        ),
        "analytics_data.json": (
            '{\n'
            '  "period": "2024-Q3",\n'
            '  "visits": 152340,\n'
            '  "unique_users": 89210,\n'
            '  "bounce_rate": 0.34,\n'
            '  "avg_session_duration": 245,\n'
            '  "top_pages": [\n'
            '    {"/dashboard": 45000},\n'
            '    {"/products": 32000},\n'
            '    {"/checkout": 18000}\n'
            '  ],\n'
            '  "conversion_rate": 0.042\n'
            '}\n'
        ),
        "presentation.pptx": (
            "Board Meeting - Strategic Review\n\n"
            "Slide 1: Executive Summary\n"
            "Revenue up 18% YoY. Customer acquisition cost down 12%.\n\n"
            "Slide 2: Market Analysis\n"
            "TAM expanded to $2.4B with entry into APAC region.\n\n"
            "Slide 3: Product Roadmap\n"
            "V3.0 launch scheduled Q1. Key features: real-time collaboration, "
            "advanced analytics, SSO integration.\n\n"
            "Slide 4: Financial Projections\n"
            "Targeting $15M ARR by EOY with current growth trajectory.\n"
        ),
        "inventory.csv": (
            "item_id,name,quantity,unit_price,warehouse\n"
            "1001,Widget-A,500,12.99,EAST\n"
            "1002,Widget-B,320,24.50,EAST\n"
            "1003,Gadget-X,150,89.99,WEST\n"
            "1004,Module-C,800,7.25,EAST\n"
            "1005,Assembly-D,45,210.00,WEST\n"
            "1006,Component-E,1200,3.50,EAST\n"
        ),
        "infrastructure_notes.txt": (
            "Deployment pipeline documentation\n\n"
            "Build: GitHub Actions -> Docker image -> ECR\n"
            "Deploy: ArgoCD watches main branch, auto-syncs to k8s cluster\n"
            "Rollback: kubectl rollout undo deployment/<name>\n\n"
            "Monitoring stack: Prometheus + Grafana\n"
            "Alerting: PagerDuty integration via Alertmanager\n"
            "Log aggregation: Fluentd -> Elasticsearch -> Kibana\n"
        ),
    }

    for filename, content in sample_files.items():
        filepath = os.path.join(config.SANDBOX_DIR, filename)
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                f.write(content)

    print(f"[SETUP] Sandbox ready: {len(sample_files)} files in {config.SANDBOX_DIR}")


if __name__ == "__main__":
    create_sandbox()
