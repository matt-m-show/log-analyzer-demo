# Handles OAuth2 authentication for the Google Admin SDK Reports API

import os
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Scopes required to read audit and usage reports from the Admin SDK
SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
]

_ROOT = Path(__file__).parent.parent
_CREDENTIALS_FILE = _ROOT / "credentials.json"
_TOKEN_FILE = _ROOT / "token.json"


def get_reports_service():
    """Authenticate with OAuth2 and return an Admin SDK Reports API service object.

    On first run, opens a browser window to complete the OAuth2 flow and writes
    a refresh token to token.json. Subsequent runs load the saved token and
    refresh it silently if expired, without requiring browser interaction.

    Returns:
        A googleapiclient Resource object authenticated against the Reports API.

    Raises:
        FileNotFoundError: If credentials.json is not found in the project root.
    """
    if not _CREDENTIALS_FILE.exists():
        raise FileNotFoundError(
            f"credentials.json not found at {_CREDENTIALS_FILE}. "
            "Download it from the Google Cloud Console and place it in the project root."
        )

    creds = None

    # Load existing token if available
    if _TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(_TOKEN_FILE), SCOPES)

    # Refresh or perform full OAuth2 flow if needed
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(_CREDENTIALS_FILE), SCOPES
            )
            creds = flow.run_local_server(port=0)

        # Persist the token so subsequent runs skip the browser step
        _TOKEN_FILE.write_text(creds.to_json())

    return build("admin", "reports_v1", credentials=creds)
