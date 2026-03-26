# Named constants for detection thresholds and configuration

# Number of failed login attempts from a single IP before a failed-login alert is raised
MAX_FAILED_LOGINS: int = 5

# Rolling time window (in seconds) used to evaluate brute force attempt frequency
BRUTE_FORCE_WINDOW_SECONDS: int = 60

# Number of failed attempts within BRUTE_FORCE_WINDOW_SECONDS that triggers a brute force alert
BRUTE_FORCE_ATTEMPT_THRESHOLD: int = 10

# IPs that should never trigger alerts (e.g. internal scanners, monitoring agents)
SAFE_IPS: list[str] = []

# Log types the application can parse; used for CLI validation and parser selection
SUPPORTED_LOG_TYPES: list[str] = ["auth", "web"]

# OAuth client IDs that are known-good and should never trigger suspicious OAuth alerts.
# To add a new entry, append a dict with client_id, app_name, and reason keys:
#   {"client_id": "...", "app_name": "My App", "reason": "Internal tool approved by IT"}
WORKSPACE_OAUTH_WHITELIST: list[dict] = [
    {
        "client_id": "25663159623-1soas5jk7k62d6tni7oulrjeib95j4dc.apps.googleusercontent.com",
        "app_name":  "Claude for Google Drive",
        "reason":    "Anthropic first-party integration, approved for use",
    },
    {
        "client_id": "101988054943-3c90eajaph0d76bpa6bejkf74hhdatpq.apps.googleusercontent.com",
        "app_name":  "Claude for Gmail",
        "reason":    "Anthropic first-party integration, approved for use",
    },
    {
        "client_id": "181481259367-kqbftmnd121er1dmpvss7l4bjfpt5c3h.apps.googleusercontent.com",
        "app_name":  "Claude for Google Calendar",
        "reason":    "Anthropic first-party integration, approved for use",
    },
    {
        "client_id": "231591978307-qjdvnjijal369dgfbch0ja2ti0s10c11.apps.googleusercontent.com",
        "app_name":  "Log-Analytics",
        "reason":    "Internal log analysis service account, verified",
    },
]
