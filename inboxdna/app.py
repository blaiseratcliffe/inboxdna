"""InboxDNA - Local-first Gmail inbox analyzer and cleanup tool."""

import base64
import functools
import json
import random
import re
import os
import secrets
import time
from collections import Counter, defaultdict
from email.utils import parsedate_to_datetime
from flask import Flask, render_template, request, jsonify
from googleapiclient.errors import HttpError
import ssl
from inboxdna.auth import get_gmail_service, invalidate_service, AuthError
from inboxdna.classifiers import KNOWN_TRACKER_DOMAINS, SENSITIVE_PATTERNS
from inboxdna import paths
import inboxdna.db as db


# --- Retry decorator for transient Gmail API errors + SSL recovery ---

def gmail_retry(max_retries=3, base_delay=1.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ssl.SSLError, TimeoutError, ConnectionError, OSError) as e:
                    # Stale/dead SSL connection — force rebuild
                    invalidate_service()
                    if attempt < max_retries - 1:
                        time.sleep(base_delay * (attempt + 1))
                        continue
                    raise
                except HttpError as e:
                    if e.resp.status in (429, 500, 503) and attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        time.sleep(delay)
                        continue
                    raise
        return wrapper
    return decorator


# --- Request validation decorators ---

def require_json(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    return decorated


# --- Input validation for message_ids ---

GMAIL_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
MAX_MESSAGE_IDS = 10000


def validate_message_ids(data):
    """Extract and validate message_ids from request JSON.
    Returns (ids, error_response). error_response is None on success."""
    ids = data.get("message_ids", [])
    if not isinstance(ids, list):
        return None, (jsonify({"error": "message_ids must be a list"}), 400)
    if len(ids) > MAX_MESSAGE_IDS:
        return None, (jsonify({"error": f"Too many message IDs (max {MAX_MESSAGE_IDS})"}), 400)
    for mid in ids:
        if not isinstance(mid, str) or not GMAIL_ID_RE.match(mid):
            return None, (jsonify({"error": "Invalid message ID format"}), 400)
    return ids, None


app = Flask(__name__,
            template_folder=os.path.join(paths.PACKAGE_DIR, "templates"),
            static_folder=os.path.join(paths.PACKAGE_DIR, "static"))


def _get_or_create_secret_key():
    """Load secret key from persistent file, creating if needed."""
    key_file = os.path.join(paths.USER_DATA_DIR, ".flask_secret")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


app.secret_key = _get_or_create_secret_key()

# Lazy database initialization — runs once on first request instead of at import time
_db_initialized = False

@app.before_request
def _ensure_db():
    global _db_initialized
    if not _db_initialized:
        db.init_db()
        _db_initialized = True


# --- CSRF protection: validate Origin on mutating requests ---

ALLOWED_ORIGINS = (
    "http://localhost:5000",
    "http://127.0.0.1:5000",
)


@app.before_request
def check_origin():
    """Reject mutating requests from non-localhost origins."""
    if request.method in ("POST", "PUT", "DELETE"):
        origin = request.headers.get("Origin", "")
        referer = request.headers.get("Referer", "")
        if origin and origin not in ALLOWED_ORIGINS:
            return jsonify({"error": "Forbidden: invalid origin"}), 403
        if not origin and referer and not any(referer.startswith(a) for a in ALLOWED_ORIGINS):
            return jsonify({"error": "Forbidden: invalid referer"}), 403


# --- Security headers ---

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# --- Global error handlers ---

@app.errorhandler(HttpError)
def handle_gmail_error(e):
    status = e.resp.status
    if status == 401:
        return jsonify({"error": "Gmail auth expired. Delete token.json and restart."}), 401
    if status == 429:
        return jsonify({"error": "Gmail rate limit. Try again shortly."}), 429
    return jsonify({"error": f"Gmail API error: {e._get_reason()}"}), status


@app.errorhandler(ssl.SSLError)
def handle_ssl_error(e):
    invalidate_service()
    return jsonify({"error": "Connection reset. Please try again."}), 503


@app.errorhandler(TimeoutError)
def handle_timeout(e):
    invalidate_service()
    return jsonify({"error": "Gmail API timed out. Please try again."}), 504


@app.errorhandler(AuthError)
def handle_auth_error(e):
    return jsonify({"error": str(e), "auth_failed": True}), 401


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(Exception)
def handle_unexpected(e):
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500


# --- Marketing / spam classification ---

MARKETING_SENDER_KEYWORDS = [
    "noreply", "no-reply", "newsletter", "marketing", "mailer-daemon",
    "notifications", "updates", "promo", "campaign", "bulk", "bounce",
    "donotreply", "email.campaign", "mailchimp", "sendgrid", "mailgun",
    "amazonses", "postmaster",
]

MARKETING_DOMAINS = {
    "noreply", "no-reply", "newsletter", "news", "marketing", "promo",
    "promotions", "deals", "offers", "info", "notifications", "notify",
    "updates", "mailer", "campaign", "bulk", "bounce", "hello", "team",
    "support", "digest", "alerts", "subscriptions", "unsubscribe",
}

MARKETING_SUBJECT_PATTERNS = [
    r"(?i)\b(unsubscribe|opt.?out)\b",
    r"(?i)\b(sale|discount|off|deal|coupon|promo|save|free|limited.?time)\b",
    r"(?i)\b(order confirm|shipping|tracking|delivery)\b",
    r"(?i)\b(newsletter|weekly|monthly|digest|roundup)\b",
    r"(?i)\b(your?.account|security.?alert|verify|confirm)\b",
    r"(?i)\b(reward|points|cashback|loyalty|earn)\b",
    r"(?i)\b(new.?arrivals?|just.?dropped|trending|best.?sellers?)\b",
]


def classify_marketing(email_addr, subject, headers_raw, category):
    score = 0
    email_lower = email_addr.lower()

    if category == "Promotions":
        score += 50
    elif category == "Social":
        score += 30
    elif category == "Updates":
        score += 15
    elif category == "Forums":
        score += 10

    local = email_lower.split("@")[0] if "@" in email_lower else ""
    for kw in MARKETING_SENDER_KEYWORDS:
        if kw in local:
            score += 20
            break

    domain = email_lower.split("@")[1] if "@" in email_lower else ""
    if any(part in MARKETING_DOMAINS for part in domain.split(".")):
        score += 10

    for pattern in MARKETING_SUBJECT_COMPILED:
        if pattern.search(subject or ""):
            score += 10
            break

    if headers_raw.get("List-Unsubscribe"):
        score += 30

    precedence = (headers_raw.get("Precedence") or "").lower()
    if precedence in ("bulk", "list", "junk"):
        score += 25

    if headers_raw.get("X-Campaign") or headers_raw.get("X-Mailchimp-Campaign"):
        score += 20

    return min(score, 100)


# --- Helpers ---

def get_service():
    """Get Gmail service, cached to avoid rebuilding on every call."""
    return get_gmail_service()


def parse_sender(from_header):
    if "<" in from_header:
        name = from_header.split("<")[0].strip().strip('"')
        email = from_header.split("<")[1].split(">")[0]
        if not name:
            name = email
    else:
        name = from_header
        email = from_header
    return name, email


def parse_date(date_str):
    """Best-effort parse of email Date header to epoch."""
    if not date_str:
        return 0
    try:
        return int(parsedate_to_datetime(date_str).timestamp())
    except Exception:
        return 0


CLASSIFY_HEADERS = ["From", "Subject", "Date", "List-Unsubscribe", "Precedence",
                    "X-Campaign", "X-Mailchimp-Campaign", "X-Mailer"]


@gmail_retry(max_retries=3, base_delay=1.0)
def fetch_inbox_messages(max_results=500, unread_only=False, force_refresh=False):
    """Fetch inbox messages. max_results=0 means fetch ALL.
    Uses SQLite cache: only fetches metadata for messages not already cached."""
    service = get_service()
    all_messages = []
    page_token = None
    fetch_all = (max_results == 0)

    label_ids = ["INBOX"]
    if unread_only:
        label_ids.append("UNREAD")

    # Step 1: List message IDs from Gmail (cheap — just IDs)
    while fetch_all or len(all_messages) < max_results:
        batch_size = 500 if fetch_all else min(500, max_results - len(all_messages))
        results = service.users().messages().list(
            userId="me", labelIds=label_ids, maxResults=batch_size,
            pageToken=page_token
        ).execute()
        batch = results.get("messages", [])
        if not batch:
            break
        all_messages.extend(batch)
        page_token = results.get("nextPageToken")
        if not page_token:
            break

    listed_ids = {msg["id"] for msg in all_messages}

    # Step 2: Check cache for already-fetched messages
    cached_ids = db.get_cached_message_ids()

    if force_refresh:
        new_ids = listed_ids
    else:
        new_ids = listed_ids - cached_ids

    # Step 3: Fetch metadata only for NEW messages from Gmail API
    if new_ids:
        new_messages_list = [msg for msg in all_messages if msg["id"] in new_ids]
        fetched = {}

        def _make_callback(msg_id):
            def callback(request_id, response, exception):
                if exception is None:
                    fetched[msg_id] = response
            return callback

        for i in range(0, len(new_messages_list), 100):
            chunk = new_messages_list[i:i + 100]
            batch_req = service.new_batch_http_request()
            for msg in chunk:
                batch_req.add(
                    service.users().messages().get(
                        userId="me", id=msg["id"], format="metadata",
                        metadataHeaders=CLASSIFY_HEADERS
                    ),
                    callback=_make_callback(msg["id"])
                )
            batch_req.execute()

        # Parse and cache new messages
        new_parsed = []
        for msg_id, full in fetched.items():
            headers = {h["name"]: h["value"] for h in full["payload"]["headers"]}
            labels = full.get("labelIds", [])
            name, email = parse_sender(headers.get("From", "unknown"))
            size_estimate = full.get("sizeEstimate", 0)

            category = "Other"
            for label in labels:
                if label.startswith("CATEGORY_"):
                    category = label.replace("CATEGORY_", "").title()
                    break

            subject = headers.get("Subject", "(no subject)")
            spam_score = classify_marketing(email, subject, headers, category)
            date_str = headers.get("Date", "")
            epoch = parse_date(date_str)

            new_parsed.append({
                "id": msg_id,
                "from_name": name,
                "from_email": email,
                "subject": subject,
                "snippet": full.get("snippet", ""),
                "date": date_str,
                "epoch": epoch,
                "unread": "UNREAD" in labels,
                "category": category,
                "spam_score": spam_score,
                "has_unsubscribe": bool(headers.get("List-Unsubscribe")),
                "size": size_estimate,
            })

        db.upsert_messages(new_parsed)

    # Step 4: Prune stale entries (messages no longer in inbox)
    stale_ids = cached_ids - listed_ids
    if stale_ids:
        db.delete_messages(stale_ids)

    # Step 5: Return the set of listed IDs (caller uses SQL aggregation)
    return listed_ids


# --- Routes ---

@app.route("/api/auth_status")
def api_auth_status():
    """Check if user is signed in (token exists and is valid)."""
    from inboxdna.auth import TOKEN_FILE
    has_token = os.path.exists(TOKEN_FILE)
    return jsonify({"signed_in": has_token})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sender_messages")
def api_sender_messages():
    """Return cached messages for a sender email (lightweight, from DB)."""
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400
    msgs = db.get_cached_messages_for_sender(email)
    return jsonify(msgs)


@app.route("/api/sender_ids")
def api_sender_ids():
    """Return message IDs for a sender (lightweight, for actions)."""
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400
    ids = db.get_message_ids_for_sender(email)
    return jsonify({"message_ids": ids})


@app.route("/api/scan")
def api_scan():
    try:
        max_results = int(request.args.get("limit", 500))
    except (ValueError, TypeError):
        return jsonify({"error": "limit must be a valid integer"}), 400
    if max_results < 0:
        max_results = 0

    unread_only = request.args.get("unread", "false").lower() == "true"
    force_refresh = request.args.get("refresh", "false").lower() == "true"
    listed_ids = fetch_inbox_messages(max_results, unread_only=unread_only,
                                      force_refresh=force_refresh)

    # Use SQL aggregation instead of materializing all messages into Python
    sender_list = db.get_sender_aggregates(listed_ids)
    decisions = db.get_decisions()
    for entry in sender_list:
        if entry["email"] in decisions:
            entry["decision"] = decisions[entry["email"]]["decision"]

    sender_list.sort(key=lambda s: s["count"], reverse=True)
    total = sum(s["count"] for s in sender_list)
    total_unread = sum(s["unread"] for s in sender_list)
    total_size = sum(s["total_size"] for s in sender_list)

    # Save snapshot for Time Machine
    marketing_count = sum(1 for s in sender_list if s["spam_score"] >= 50)
    human_count = sum(1 for s in sender_list if s["spam_score"] < 30 and not s["has_unsubscribe"])
    snapshot_id = db.save_scan_snapshot(total, total_unread, len(sender_list),
                                        total_size, marketing_count, human_count)
    db.save_sender_history(snapshot_id, sender_list)

    return jsonify({
        "total": total,
        "total_unread": total_unread,
        "total_size": total_size,
        "senders": sender_list,
    })


@app.route("/api/stats")
def api_stats():
    return jsonify(db.load_stats())


@app.route("/api/decisions")
def api_decisions():
    return jsonify(db.get_decisions())


@app.route("/api/labels")
@gmail_retry(max_retries=3, base_delay=1.0)
def api_labels():
    service = get_service()
    results = service.users().labels().list(userId="me").execute()
    labels = [
        {"id": l["id"], "name": l["name"], "type": l["type"]}
        for l in results.get("labels", [])
        if l["type"] == "user"
    ]
    labels.sort(key=lambda l: l["name"])
    return jsonify(labels)


@app.route("/api/labels/create", methods=["POST"])
@require_json
def api_create_label():
    service = get_service()
    name = request.json.get("name")
    if not name:
        return jsonify({"error": "Name required"}), 400
    label = service.users().labels().create(
        userId="me", body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
    ).execute()
    return jsonify({"id": label["id"], "name": label["name"]})


@app.route("/api/archive", methods=["POST"])
@require_json
def api_archive():
    service = get_service()
    message_ids, err = validate_message_ids(request.json)
    if err:
        return err
    if not message_ids:
        return jsonify({"error": "No messages specified"}), 400

    sender = request.json.get("sender", "")
    db.push_undo("archive", message_ids)

    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        service.users().messages().batchModify(
            userId="me",
            body={"ids": batch, "removeLabelIds": ["INBOX"]}
        ).execute()

    if sender:
        db.log_triage_action(sender, "", "archive", "list", len(message_ids))
    db.delete_messages(message_ids)
    db.increment_stats(len(message_ids))
    return jsonify({"archived": len(message_ids)})


@app.route("/api/delete", methods=["POST"])
@require_json
def api_delete():
    service = get_service()
    message_ids, err = validate_message_ids(request.json)
    if err:
        return err
    if not message_ids:
        return jsonify({"error": "No messages specified"}), 400

    sender = request.json.get("sender", "")
    db.push_undo("delete", message_ids)

    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        service.users().messages().batchModify(
            userId="me",
            body={"ids": batch, "addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}
        ).execute()

    if sender:
        db.log_triage_action(sender, "", "delete", "list", len(message_ids))
    db.delete_messages(message_ids)
    db.increment_stats(len(message_ids))
    return jsonify({"deleted": len(message_ids)})


@app.route("/api/label", methods=["POST"])
@require_json
def api_apply_label():
    service = get_service()
    message_ids, err = validate_message_ids(request.json)
    if err:
        return err
    label_id = request.json.get("label_id")
    if not message_ids or not label_id:
        return jsonify({"error": "message_ids and label_id required"}), 400

    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        service.users().messages().batchModify(
            userId="me",
            body={"ids": batch, "addLabelIds": [label_id]}
        ).execute()

    return jsonify({"labeled": len(message_ids)})


@app.route("/api/mark_read", methods=["POST"])
@require_json
def api_mark_read():
    service = get_service()
    message_ids, err = validate_message_ids(request.json)
    if err:
        return err
    if not message_ids:
        return jsonify({"error": "No messages specified"}), 400

    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        service.users().messages().batchModify(
            userId="me",
            body={"ids": batch, "removeLabelIds": ["UNREAD"]}
        ).execute()

    return jsonify({"marked_read": len(message_ids)})


@app.route("/api/block", methods=["POST"])
@require_json
def api_block():
    """Block a sender: archive existing + create filter to auto-archive future."""
    service = get_service()
    data = request.json
    sender = data.get("sender")
    message_ids, err = validate_message_ids(data)
    if err:
        return err

    if not sender:
        return jsonify({"error": "sender required"}), 400

    if message_ids:
        for i in range(0, len(message_ids), 1000):
            batch = message_ids[i:i+1000]
            service.users().messages().batchModify(
                userId="me",
                body={"ids": batch, "removeLabelIds": ["INBOX"]}
            ).execute()
        db.delete_messages(message_ids)
        db.increment_stats(len(message_ids))

    filter_result = service.users().settings().filters().create(
        userId="me",
        body={
            "criteria": {"from": sender},
            "action": {"removeLabelIds": ["INBOX"]}
        }
    ).execute()

    filter_id = filter_result.get("id")
    db.push_undo("block", message_ids, sender=sender, filter_id=filter_id)
    db.record_decision(sender, "blocked", filter_id)
    db.log_triage_action(sender, "", "block", "list", len(message_ids))
    return jsonify({"blocked": sender, "archived": len(message_ids)})


@app.route("/api/unsubscribe_and_delete", methods=["POST"])
@require_json
def api_unsubscribe_and_delete():
    """Cleanfox-style: delete all + create filter to auto-trash future emails."""
    service = get_service()
    data = request.json
    sender = data.get("sender")
    message_ids, err = validate_message_ids(data)
    if err:
        return err

    if not sender:
        return jsonify({"error": "sender required"}), 400

    for i in range(0, len(message_ids), 1000):
        batch = message_ids[i:i+1000]
        service.users().messages().batchModify(
            userId="me",
            body={"ids": batch, "addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}
        ).execute()

    filter_result = service.users().settings().filters().create(
        userId="me",
        body={
            "criteria": {"from": sender},
            "action": {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}
        }
    ).execute()

    filter_id = filter_result.get("id")
    db.delete_messages(message_ids)
    db.increment_stats(len(message_ids))
    db.push_undo("unsubscribe_delete", message_ids, sender=sender, filter_id=filter_id)
    db.record_decision(sender, "unsubscribed", filter_id)
    db.log_triage_action(sender, "", "unsub", "list", len(message_ids))
    return jsonify({"unsubscribed": sender, "deleted": len(message_ids)})


@app.route("/api/filter/create", methods=["POST"])
@require_json
def api_create_filter():
    service = get_service()
    data = request.json
    sender = data.get("sender")
    action = data.get("action", {})

    if not sender:
        return jsonify({"error": "sender required"}), 400

    filter_body = {
        "criteria": {"from": sender},
        "action": {}
    }

    if action.get("archive"):
        filter_body["action"]["removeLabelIds"] = ["INBOX"]
    if action.get("label_id"):
        filter_body["action"]["addLabelIds"] = [action["label_id"]]
    if action.get("mark_read"):
        filter_body["action"]["removeLabelIds"] = filter_body["action"].get("removeLabelIds", [])
        if "UNREAD" not in filter_body["action"]["removeLabelIds"]:
            filter_body["action"]["removeLabelIds"].append("UNREAD")
    if action.get("delete"):
        filter_body["action"]["addLabelIds"] = ["TRASH"]

    if not filter_body["action"]:
        return jsonify({"error": "At least one filter action required (archive, label, mark_read, or delete)"}), 400

    result = service.users().settings().filters().create(
        userId="me", body=filter_body
    ).execute()

    return jsonify({"filter_id": result["id"]})


@app.route("/api/undo", methods=["POST"])
@require_json
def api_undo():
    """Undo last action (persisted across restarts)."""
    service = get_service()
    entry = db.pop_undo()
    if not entry:
        return jsonify({"error": "Nothing to undo"}), 400

    action = entry["action"]
    message_ids = entry.get("message_ids", [])
    filter_id = entry.get("filter_id")
    sender = entry.get("sender")

    if filter_id:
        try:
            service.users().settings().filters().delete(
                userId="me", id=filter_id
            ).execute()
        except Exception:
            pass

    if sender:
        db.remove_decision(sender)

    if action in ("archive", "block"):
        for i in range(0, len(message_ids), 1000):
            batch = message_ids[i:i+1000]
            service.users().messages().batchModify(
                userId="me",
                body={"ids": batch, "addLabelIds": ["INBOX"]}
            ).execute()
        return jsonify({"undone": action, "restored": len(message_ids)})

    elif action in ("delete", "unsubscribe_delete"):
        for i in range(0, len(message_ids), 1000):
            batch = message_ids[i:i+1000]
            service.users().messages().batchModify(
                userId="me",
                body={"ids": batch, "removeLabelIds": ["TRASH"], "addLabelIds": ["INBOX"]}
            ).execute()
        return jsonify({"undone": action, "restored": len(message_ids)})

    return jsonify({"undone": action})


# --- Message preview endpoint ---

@app.route("/api/message/<message_id>")
def api_message_detail(message_id):
    service = get_service()
    msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()
    payload = msg["payload"]
    body_text = _extract_text_body(payload)
    headers = {h["name"]: h["value"] for h in payload.get("headers", [])}
    return jsonify({
        "id": message_id,
        "subject": headers.get("Subject", ""),
        "from": headers.get("From", ""),
        "date": headers.get("Date", ""),
        "snippet": msg.get("snippet", ""),
        "body_text": body_text[:5000],
    })


# --- List Gmail filters endpoint ---

@app.route("/api/filters")
def api_list_filters():
    service = get_service()
    results = service.users().settings().filters().list(userId="me").execute()
    filters = []
    for f in results.get("filter", []):
        criteria = f.get("criteria", {})
        action = f.get("action", {})
        filters.append({
            "id": f["id"],
            "from": criteria.get("from", ""),
            "subject": criteria.get("subject", ""),
            "archive": "INBOX" in action.get("removeLabelIds", []),
            "trash": "TRASH" in action.get("addLabelIds", []),
            "mark_read": "UNREAD" in action.get("removeLabelIds", []),
        })
    return jsonify({"filters": filters})


# --- Time Machine (Feature 6) ---

@app.route("/api/time_machine")
def api_time_machine():
    snapshots = db.get_snapshots(52)
    growth = db.get_growth_rate()
    new_senders = db.get_new_senders_since(int(time.time()) - 30 * 86400)
    composition = db.get_composition_shift(4)
    return jsonify({
        "snapshots": snapshots,
        "growth": growth,
        "new_senders": new_senders,
        "composition": composition,
    })


# --- Hygiene Score (Feature 1) ---

@app.route("/api/hygiene_score")
def api_hygiene_score():
    score_data = db.compute_hygiene_score()
    db.save_hygiene_score(score_data)
    new_badges = db.check_and_award_badges()
    return jsonify({
        **score_data,
        "history": db.get_hygiene_history(12),
        "streak": db.get_hygiene_streak(),
        "badges": db.get_badges(),
        "new_badges": new_badges,
    })


# --- Decay Radar (Feature 3) ---

@app.route("/api/decay_radar")
def api_decay_radar():
    decaying = db.get_decaying_subscriptions()
    return jsonify({"decaying_senders": decaying})


# --- Storage Cost Visualizer (Feature 2) ---

@app.route("/api/storage")
def api_storage():
    senders = db.get_storage_by_sender(50)
    summary = db.get_storage_summary()
    hoarders = db.get_attachment_hoarders()

    total_bytes = summary.get("total_size", 0) or 0
    free_tier = 15 * 1024 * 1024 * 1024  # 15 GB
    # Estimate: Gmail is ~25% of Google storage for typical users
    estimated_gmail_total = total_bytes * 4  # rough estimate of full mailbox
    pct_used = round(estimated_gmail_total / free_tier * 100, 1) if free_tier else 0

    # Google One pricing
    monthly_cost = 0
    if estimated_gmail_total > 2 * 1024**4:
        monthly_cost = 13.99
    elif estimated_gmail_total > 200 * 1024**3:
        monthly_cost = 3.99
    elif estimated_gmail_total > 100 * 1024**3:
        monthly_cost = 2.49
    elif estimated_gmail_total > free_tier:
        monthly_cost = 2.49

    return jsonify({
        "senders": senders,
        "summary": summary,
        "hoarders": hoarders,
        "estimated_total_gb": round(estimated_gmail_total / (1024**3), 2),
        "free_tier_gb": 15,
        "pct_used": min(pct_used, 100),
        "monthly_cost": monthly_cost,
        "reclaimable_bytes": sum(s["total_size"] for s in senders[:10]),
    })


# --- Quiet Hours Heatmap (Feature 4) ---

@app.route("/api/heatmap")
def api_heatmap():
    grid = db.get_email_heatmap()
    late_night = db.get_late_night_senders()
    return jsonify({"grid": grid, "late_night_senders": late_night})


# --- Ghost Rules (Feature 7) ---

@app.route("/api/ghost_rules")
def api_ghost_rules():
    db.detect_ghost_rules()
    rules = db.get_pending_ghost_rules()
    return jsonify({"rules": rules})


@app.route("/api/ghost_rules/<int:rule_id>/accept", methods=["POST"])
@require_json
def api_accept_ghost_rule(rule_id):
    rule = db.get_ghost_rule(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    # Create the Gmail filter
    service = get_service()
    action_map = {
        "auto-archive": {"removeLabelIds": ["INBOX"]},
        "auto-delete": {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]},
        "auto-block": {"removeLabelIds": ["INBOX"]},
    }
    gmail_action = action_map.get(rule["suggested_action"], {"removeLabelIds": ["INBOX"]})

    filter_result = service.users().settings().filters().create(
        userId="me",
        body={"criteria": {"from": rule["sender_email"]}, "action": gmail_action}
    ).execute()

    db.update_ghost_rule_status(rule_id, "accepted")
    return jsonify({"accepted": True, "filter_id": filter_result.get("id")})


@app.route("/api/ghost_rules/<int:rule_id>/dismiss", methods=["POST"])
@require_json
def api_dismiss_ghost_rule(rule_id):
    db.update_ghost_rule_status(rule_id, "dismissed")
    return jsonify({"dismissed": True})


# --- Reply Debt (Feature 5) ---

@app.route("/api/reply_debt")
@gmail_retry(max_retries=3, base_delay=1.0)
def api_reply_debt():
    # Fetch sent messages if cache is empty or stale (>1 hour)
    refresh = request.args.get("refresh", "false").lower() == "true"
    if db.get_sent_count() == 0 or refresh:
        _fetch_sent_messages()
    debt = db.get_reply_debt()
    return jsonify({"unanswered": debt, "total_debt": len(debt)})


def _fetch_sent_messages(max_results=300):
    """Fetch recent sent messages and cache them."""
    service = get_service()
    all_msgs = []
    page_token = None
    while len(all_msgs) < max_results:
        batch_size = min(500, max_results - len(all_msgs))
        results = service.users().messages().list(
            userId="me", labelIds=["SENT"], maxResults=batch_size, pageToken=page_token
        ).execute()
        batch = results.get("messages", [])
        if not batch:
            break
        all_msgs.extend(batch)
        page_token = results.get("nextPageToken")
        if not page_token:
            break

    # Batch fetch To headers
    fetched = {}
    def _cb(msg_id):
        def callback(request_id, response, exception):
            if exception is None:
                fetched[msg_id] = response
        return callback

    for i in range(0, len(all_msgs), 100):
        chunk = all_msgs[i:i + 100]
        batch_req = service.new_batch_http_request()
        for msg in chunk:
            batch_req.add(
                service.users().messages().get(
                    userId="me", id=msg["id"], format="metadata",
                    metadataHeaders=["To", "Subject", "Date"]
                ),
                callback=_cb(msg["id"])
            )
        batch_req.execute()

    parsed = []
    for msg_id, full in fetched.items():
        headers = {h["name"]: h["value"] for h in full["payload"]["headers"]}
        to_raw = headers.get("To", "")
        subject = headers.get("Subject", "")
        epoch = parse_date(headers.get("Date", ""))
        # Extract all recipient emails (handles comma-separated, "Name <email>" format)
        for recipient in to_raw.split(","):
            recipient = recipient.strip()
            if "<" in recipient:
                to_email = recipient.split("<")[1].split(">")[0]
            else:
                to_email = recipient
            to_email = to_email.strip().lower()
            if to_email and "@" in to_email:
                parsed.append({
                    "id": f"{msg_id}_{to_email}",
                    "to_email": to_email,
                    "subject": subject,
                    "epoch": epoch,
                })

    db.upsert_sent_messages(parsed)


# --- Email DNA / Sender Profile (Feature 9) ---

@app.route("/api/sender_profile")
def api_sender_profile():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400
    profile = db.compute_sender_profile(email)
    if not profile:
        return jsonify({"error": "Sender not found in cache"}), 404
    return jsonify(profile)


# --- Privacy Audit (Feature 8) ---

@app.route("/api/privacy_audit", methods=["POST"])
@require_json
@gmail_retry(max_retries=3, base_delay=1.0)
def api_privacy_audit():
    """Scan recent emails for tracking pixels and sensitive data."""
    max_scan = min(int(request.json.get("max_messages", 50)), 200)
    messages = db.get_recent_message_ids(max_scan)
    service = get_service()

    # Build lookup of msg_id -> sender email
    msg_senders = {m["id"]: m["from_email"] for m in messages}

    # Batch fetch full message bodies (chunks of 50 to stay within size limits)
    fetched = {}
    msg_list = list(msg_senders.keys())

    def _make_callback(msg_id):
        def callback(request_id, response, exception):
            if exception is None:
                fetched[msg_id] = response
        return callback

    for i in range(0, len(msg_list), 50):
        chunk = msg_list[i:i + 50]
        batch_req = service.new_batch_http_request()
        for msg_id in chunk:
            batch_req.add(
                service.users().messages().get(
                    userId="me", id=msg_id, format="full"
                ),
                callback=_make_callback(msg_id)
            )
        batch_req.execute()

    # Process fetched messages
    all_findings = []
    scanned = 0
    for msg_id, full in fetched.items():
        try:
            from_email = msg_senders.get(msg_id, "")
            html_body = _extract_html_body(full.get("payload", {}))
            text_body = _extract_text_body(full.get("payload", {}))

            trackers = _detect_tracking_pixels(html_body)
            for t in trackers:
                all_findings.append((msg_id, from_email, "tracking_pixel", json.dumps(t), "low"))

            sensitive = _detect_sensitive_data(text_body)
            for s in sensitive:
                all_findings.append((msg_id, from_email, "sensitive_data", json.dumps(s), s["severity"]))
            scanned += 1
        except Exception:
            continue

    # Batch save all findings in one commit
    db.save_privacy_findings_batch(all_findings)

    report = db.get_privacy_report()
    report["just_scanned"] = scanned
    return jsonify(report)


@app.route("/api/privacy_report")
def api_privacy_report():
    return jsonify(db.get_privacy_report())


def _extract_mime_part(payload, target_mime):
    """Extract body content for a given MIME type from a Gmail payload."""
    result = ""
    def walk(part):
        nonlocal result
        mime = part.get("mimeType", "")
        if mime == target_mime and "data" in part.get("body", {}):
            result = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="replace")
        for sub in part.get("parts", []):
            walk(sub)
    walk(payload)
    return result


def _extract_html_body(payload):
    return _extract_mime_part(payload, "text/html")


def _extract_text_body(payload):
    return _extract_mime_part(payload, "text/plain")


# Pre-compiled regex patterns for tracking pixel detection
_IMG_1X1_RE = re.compile(
    r'<img[^>]*(?:width\s*=\s*["\']?1["\']?[^>]*height\s*=\s*["\']?1["\']?|'
    r'height\s*=\s*["\']?1["\']?[^>]*width\s*=\s*["\']?1["\']?)[^>]*>', re.I
)
_IMG_SRC_RE = re.compile(r'<img[^>]*src\s*=\s*["\']([^"\']+)["\']', re.I)

# Pre-compile marketing subject patterns
MARKETING_SUBJECT_COMPILED = [re.compile(p) for p in MARKETING_SUBJECT_PATTERNS]


def _detect_tracking_pixels(html):
    if not html:
        return []
    findings = []
    for m in _IMG_1X1_RE.finditer(html):
        findings.append({"type": "1x1_pixel", "snippet": m.group()[:150]})
    for m in _IMG_SRC_RE.finditer(html):
        url = m.group(1)
        for domain in KNOWN_TRACKER_DOMAINS:
            if domain in url:
                findings.append({"type": "tracker_domain", "domain": domain, "url": url[:150]})
                break
    return findings


def _detect_sensitive_data(text):
    if not text:
        return []
    findings = []
    for name, pattern, severity in SENSITIVE_PATTERNS:
        if re.search(pattern, text):
            findings.append({"name": name, "severity": severity})
    return findings


# --- Cache management ---

@app.route("/api/cache/clear", methods=["POST"])
@require_json
def api_clear_cache():
    db.clear_all_messages()
    return jsonify({"cleared": True})


@app.route("/api/logout", methods=["POST"])
@require_json
def api_logout():
    """Sign out: remove OAuth token and clear message cache."""
    from inboxdna.auth import TOKEN_FILE, invalidate_service
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
    invalidate_service()
    db.clear_all_messages()
    return jsonify({"logged_out": True})


@app.route("/api/logout/full", methods=["POST"])
@require_json
def api_logout_full():
    """Sign out and delete all local data (database, stats, token)."""
    global _db_initialized
    from inboxdna.auth import TOKEN_FILE, invalidate_service
    invalidate_service()
    # Close the database connection before deleting (required on Windows)
    db.close_db()
    _db_initialized = False
    files_to_delete = [
        TOKEN_FILE,
        db.DB_PATH,
        db.DB_PATH + "-wal",
        db.DB_PATH + "-shm",
        db.STATS_JSON,
        os.path.join(paths.USER_DATA_DIR, ".flask_secret"),
    ]
    for f in files_to_delete:
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError:
            pass
    return jsonify({"logged_out": True, "data_deleted": True})


def main():
    """Entry point for the CLI and python -m inboxdna."""
    import threading
    import webbrowser

    port = 5000
    url = f"http://localhost:{port}"

    print(f"InboxDNA v{__import__('inboxdna').__version__}")
    print(f"Opening {url}")
    print(f"Data: {paths.USER_DATA_DIR}")
    print(f"Press Ctrl+C to quit")

    # Open browser after a short delay (server needs to start first)
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    try:
        from waitress import serve
        serve(app, host="127.0.0.1", port=port)
    except ImportError:
        # Fall back to Flask dev server if waitress not installed
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(debug=False, host="127.0.0.1", port=port, threaded=True)


if __name__ == "__main__":
    main()
