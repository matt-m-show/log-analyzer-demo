# Log Analyzer

A Python tool that parses authentication logs, web server logs, and Google Workspace audit logs to detect suspicious activity — failed SSH logins, brute force attempts, anomalous OAuth grants, and admin changes. Includes a Flask dashboard for reviewing and triaging alerts.

## Architecture

```
Local files                     Google Workspace
     │                                 │
     ▼                                 ▼
auth_parser / web_parser     workspace_parser (Reports API)
     │                                 │
     └──────────────┬──────────────────┘
                    ▼
            LogEntry objects
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
 failed_login  brute_force  workspace_detectors
       │            │            │
       └────────────┴────────────┘
                    │
              Alert objects
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   console / JSON         Flask dashboard
    reporters             (dashboard/app.py)
          │
    logs/alerts.json  ←─  scheduler.py (runs every 6 hours)
```

## Requirements

- **Python 3.10+**
- **Git for Windows** (Windows only — required for the bash shell Claude Code uses)
- **Docker Desktop** (optional — for containerized deployment)
- **Google Workspace account with Super Admin access** (required for Workspace log fetching only)

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

All detection, parsing, and reporting functionality uses the Python standard library only. The Google API packages and Flask are only needed for Workspace integration and the dashboard.

### 2. Set up Google Cloud credentials (Workspace mode only)

1. Go to the [Google Cloud Console](https://console.cloud.google.com) and create a new project.
2. Enable the **Admin SDK API** (also called Reports API) for the project.
3. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**.
4. Set the application type to **Desktop app**.
5. Download the credentials and save the file as `credentials.json` in the project root.
6. Ensure your Google account has **Super Admin** or **Reports Admin** privileges in Google Workspace.

`credentials.json` is listed in `.gitignore` and will never be committed.

### 3. Authenticate (first run)

The first time you run any Workspace command, a browser window will open asking you to authorize access. After completing the flow, a `token.json` file is saved to the project root so subsequent runs are non-interactive.

```bash
python auth/test_auth.py
```

A successful run prints the list of available Reports API applications and confirms the connection is working.

## Usage

### Analyze a local auth log

```bash
python log_analyzer/main.py --file /var/log/auth.log --type auth
```

### Analyze a local web server log

```bash
python log_analyzer/main.py --file /var/log/nginx/access.log --type web --reporter json
```

### Fetch live Google Workspace audit logs

```bash
python log_analyzer/main.py --type workspace --lookback 24
```

`--lookback` controls how many hours back to fetch (default: 6). `--file` is ignored in workspace mode.

### Run the scheduler (continuous monitoring)

```bash
python scheduler.py
```

Runs the full Workspace pipeline every 6 hours and appends alerts to `logs/alerts.json` in JSONL format. Handles errors gracefully — a failed run logs the error and waits for the next interval.

### Run the Flask dashboard

```bash
cd "C:\Users\mmcmanu\Desktop\Claude\Log Analyzer"
python dashboard/app.py
```

Then open [http://localhost:5000](http://localhost:5000). The dashboard reads from `logs/alerts.json`, supports filtering by severity and source, and lets you update alert status (new / in progress / resolved / resolved — no action). Status is persisted to `logs/alert_status.json`.

### Run the test suite

Run all tests from the `log_analyzer/` directory:

```bash
cd log_analyzer
python -m unittest discover -s tests -v
```

Run a single test module:

```bash
python -m unittest tests.test_parsers -v
python -m unittest tests.test_detectors -v
python -m unittest tests.test_reporters -v
```

## Configuration

All tunable constants live in `log_analyzer/config.py`.

### Detection thresholds

| Constant | Default | Controls |
|---|---|---|
| `MAX_FAILED_LOGINS` | `5` | Failed logins from one IP before a low-severity alert fires |
| `BRUTE_FORCE_WINDOW_SECONDS` | `60` | Rolling time window for brute force detection |
| `BRUTE_FORCE_ATTEMPT_THRESHOLD` | `10` | Failed attempts within the window before a high-severity alert fires |

### Excluding IPs from alerting

Add trusted IPs (internal scanners, monitoring agents) to `SAFE_IPS`:

```python
SAFE_IPS: list[str] = ["10.0.0.5", "10.0.0.12"]
```

To load additional IPs at runtime without modifying `config.py`:

```python
safe_ips = config.SAFE_IPS + loaded_ips  # creates a new list, does not mutate config
```

### OAuth whitelist

`WORKSPACE_OAUTH_WHITELIST` suppresses suspicious OAuth alerts for known-good apps. Each entry is a dict with three keys:

```python
WORKSPACE_OAUTH_WHITELIST = [
    {
        "client_id": "123456789-abc.apps.googleusercontent.com",
        "app_name":  "My Internal Tool",
        "reason":    "Approved by IT on 2026-03-01",
    },
]
```

The `client_id` is matched against the `client_id` field extracted from Workspace token audit events.

## Project Structure

```
├── log_analyzer/          Core pipeline package (parse → detect → report)
│   ├── main.py            CLI entry point
│   ├── models.py          Frozen dataclasses: LogEntry and Alert
│   ├── config.py          All tunable constants and whitelists
│   ├── parsers/           One parser per log type
│   ├── detectors/         Stateful detection rules (brute force, failed login)
│   ├── reporters/         Console and JSON output formatters
│   └── tests/             Unit tests and fixture log files
├── parsers/
│   └── workspace_parser.py   Google Workspace Reports API → LogEntry objects
├── detectors/
│   └── workspace_detectors.py  Four Workspace-specific detection rules
├── auth/
│   ├── google_auth.py     OAuth2 flow, token caching, service object factory
│   └── test_auth.py       Standalone connectivity test script
├── dashboard/
│   └── app.py             Flask dashboard with alert cards and status management
├── scheduler.py           6-hour polling loop, writes to logs/alerts.json
├── requirements.txt       Google API and Flask dependencies
└── logs/                  Runtime output (gitignored)
    ├── alerts.json        JSONL alert log written by scheduler
    └── alert_status.json  Key/value store for alert triage status
```

## Contributing

This project was built as a learning exercise using [Claude Code](https://claude.ai/code). If you extend it, the main extension points are:

- **New log formats** — add a parser to `log_analyzer/parsers/` following the same interface as `auth_parser.py`
- **New detection rules** — add a detector function to `log_analyzer/detectors/` accepting `list[LogEntry]` and returning `list[Alert]`, then wire it into `main.py`
- **New reporters** — add a reporter to `log_analyzer/reporters/` accepting `list[Alert]`
