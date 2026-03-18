"""Classification constants and detection patterns for InboxDNA.

Moved from db.py to separate business logic from database operations.
"""

DARK_PATTERNS = [
    ("fake_urgency", r"(?i)\b(act now|last chance|expires? today|limited time|hurry|don't miss|final notice|urgent)\b"),
    ("guilt_trip", r"(?i)\b(we miss you|don't leave|come back|abandoned|forgot about us|we noticed you haven't)\b"),
    ("fomo", r"(?i)\b(everyone is|selling fast|almost gone|only \d+ left|going fast)\b"),
    ("fake_reply", r"(?i)^re:\s"),
    ("clickbait", r"(?i)\b(you won't believe|shocking|secret|revealed|this one trick)\b"),
]

KNOWN_TRACKER_DOMAINS = [
    "mailchimp.com", "sendgrid.net", "mailgun.org", "constantcontact.com",
    "hubspot.com", "pardot.com", "marketo.net", "exacttarget.com",
    "list-manage.com", "convertkit.com", "pixel.watch", "click.pstmrk.it",
    "mandrillapp.com", "sparkpostmail.com", "amazonses.com", "sailthru.com",
    "litmus.com", "returnpath.net", "google-analytics.com",
]

SENSITIVE_PATTERNS = [
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", "critical"),
    ("Credit Card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "critical"),
    ("Password", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", "high"),
    ("API Key", r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?\S{16,}", "high"),
]
