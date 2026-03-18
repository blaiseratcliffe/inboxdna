"""Gmail API authentication with error recovery."""

import glob
import os
import ssl
import threading
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from inboxdna.paths import PACKAGE_DIR, USER_DATA_DIR

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]

TOKEN_FILE = os.path.join(USER_DATA_DIR, "token.json")


class AuthError(Exception):
    """Raised when Gmail authentication fails."""
    pass


def _find_credentials_file():
    """Find OAuth credentials: user-provided credentials.json in data dir takes
    priority, then bundled client_secret_*.json from the package."""
    user_creds = os.path.join(USER_DATA_DIR, "credentials.json")
    if os.path.exists(user_creds):
        return user_creds
    bundled = glob.glob(os.path.join(PACKAGE_DIR, "client_secret_*.json"))
    if bundled:
        return bundled[0]
    raise FileNotFoundError(
        "No OAuth credentials found. Expected client_secret_*.json in the "
        "package directory. See README.md for setup instructions."
    )


CREDENTIALS_FILE = _find_credentials_file()

# Cache the Gmail service object to avoid rebuilding on every call
_service_cache = {"service": None, "creds": None}
_service_lock = threading.Lock()


def invalidate_service():
    """Force rebuild of service on next call (e.g., after SSL error)."""
    with _service_lock:
        _service_cache["service"] = None
        _service_cache["creds"] = None


def _build_service(creds):
    """Build a fresh Gmail API service."""
    from googleapiclient.discovery import build
    return build("gmail", "v1", credentials=creds)


def _delete_token():
    """Remove a corrupt or invalid token file."""
    try:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
    except OSError:
        pass


def get_gmail_service():
    """Return an authenticated Gmail API service instance (cached, SSL-safe).
    Raises AuthError if authentication fails or user cancels."""
    with _service_lock:
        creds = _service_cache["creds"]

        # Load credentials from disk if we have none cached
        if creds is None and os.path.exists(TOKEN_FILE):
            try:
                creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
            except Exception:
                # Corrupt token file — delete and start fresh
                _delete_token()
                creds = None

        # If no valid creds, refresh or run auth flow
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception:
                    # Refresh failed (revoked, expired, network error) — delete and re-auth
                    _delete_token()
                    creds = None

            if not creds or not creds.valid:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                    creds = flow.run_local_server(port=0)
                except Exception as e:
                    raise AuthError(
                        "Gmail sign-in failed. This can happen if you cancelled the sign-in, "
                        "Google returned an error, or the OAuth app is not yet published. "
                        "Click Scan Inbox to try again."
                    ) from e

                if not creds:
                    raise AuthError("Gmail sign-in was cancelled. Click Scan Inbox to try again.")

            fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as token:
                token.write(creds.to_json())

            _service_cache["creds"] = creds
            _service_cache["service"] = _build_service(creds)
        elif _service_cache["service"] is None:
            _service_cache["creds"] = creds
            _service_cache["service"] = _build_service(creds)

        return _service_cache["service"]


if __name__ == "__main__":
    service = get_gmail_service()
    profile = service.users().getProfile(userId="me").execute()
    print(f"Authenticated as: {profile['emailAddress']}")
    print(f"Total messages: {profile['messagesTotal']}")
