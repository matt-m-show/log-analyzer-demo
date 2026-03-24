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
