# Throwaway script to verify OAuth2 authentication and Reports API connectivity

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth.google_auth import get_reports_service


def main():
    print("Authenticating with Google Admin SDK...")

    try:
        service = get_reports_service()
    except FileNotFoundError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Authentication failed: {e}")
        sys.exit(1)

    print("Authentication successful.\n")
    print("Fetching available Reports API applications...")

    try:
        # activities.list requires an application name, but we can make a minimal
        # call with a known application to confirm API access is working.
        # The Admin SDK does not expose a standalone "list applications" endpoint,
        # so we probe with 'login' — the most universally available application.
        result = (
            service.activities()
            .list(userKey="all", applicationName="login", maxResults=1)
            .execute()
        )

        # A successful response (even empty) confirms auth + API access
        items = result.get("items", [])
        print("SUCCESS: Reports API is reachable.")
        print(f"  Application probed : login")
        print(f"  Activity records   : {len(items)} returned (maxResults=1)")

        if items:
            ts = items[0].get("id", {}).get("time", "unknown")
            actor = items[0].get("actor", {}).get("email", "unknown")
            print(f"  Most recent event  : {ts} by {actor}")

    except Exception as e:
        print(f"\nERROR: API call failed: {e}")
        print(
            "\nPossible causes:\n"
            "  - The authenticated account is not a Google Workspace admin\n"
            "  - The Admin SDK API is not enabled in your Google Cloud project\n"
            "  - The OAuth2 scopes were not granted during the consent screen"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
