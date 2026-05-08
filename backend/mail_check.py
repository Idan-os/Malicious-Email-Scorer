"""Lightweight email risk analysis utilities.
This module provides helpers to parse .eml content and run a small
set of heuristic checks (header injection, attachment extension
analysis, hidden link detection, authentication header checks, and
link density detection). Each check returns a numeric contribution
that `analyze_email_risk` aggregates into a final score and list of
alerts.
"""

import email, re, quopri
from email import policy
from bs4 import BeautifulSoup
import config


def parse_eml(raw_data):
    """Convert raw .eml bytes or string into an EmailMessage.

    Accepts bytes (recommended for files) or str and returns the
    parsed message using the stdlib email package and default policy.
    """
    if isinstance(raw_data, bytes):
        return email.message_from_bytes(raw_data, policy=policy.default)
    return email.message_from_string(raw_data, policy=policy.default)

def extract_body(msg):
    """Extract and decode textual parts from an email message.

    Walks all parts and concatenates `text/plain` and `text/html`
    payloads. Attempts UTF-8 decode first and falls back to latin-1
    with replacement to avoid exceptions on malformed bytes. Returns
    lower-cased text for case-insensitive checks.
    """
    body = ""
    for part in msg.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            payload = part.get_payload(decode=True)
            if payload:
                try:
                    body += payload.decode('utf-8')
                except:
                    # Fall back robustly for non-UTF8 payloads
                    body += payload.decode('latin-1', errors='replace')
    return body.lower()

def check_header_injection(raw_data):
    """Detect simple header-level injection/XSS patterns.

    Operates on the raw message bytes/string and examines only the
    header section (before the first blank line). Returns the
    configured weight when suspicious substrings are present.
    """
    raw_text = raw_data.decode('utf-8', 'ignore') if isinstance(raw_data, bytes) else str(raw_data)
    headers = re.split(r'\r?\n\r?\n', raw_text)[0].lower()
    return config.WEIGHT_HEADER_INJECTION if any(p in headers for p in config.INJECTION_PATTERNS) else 0

def check_attachments_deep(msg):
    """Assess attachments for risky extensions and simple spoofing.

    Flags known dangerous extensions and double-extension patterns
    like `invoice.pdf.exe`.
    """
    score = 0
    for part in msg.iter_attachments():
        fname = (part.get_filename() or "").lower()
        if fname.endswith(config.DANGEROUS_EXTENSIONS):
            score += config.WEIGHT_DANGEROUS_EXT

        # Spoofing heuristic: second-to-last suffix matches a normally
        # safe document/image type (e.g., pdf) followed by executable
        if fname.count('.') >= 2 and fname.split('.')[-2] in config.SAFE_DOUBLE_EXT_SUFFIXES:
            score += config.WEIGHT_DOUBLE_EXT
            
    return min(score, config.MAX_ATTACHMENT_RISK_CAP)

def check_hidden_links(body):
    """Find anchors where displayed URL differs from the real `href`.

    Decodes quoted-printable content, parses HTML with BeautifulSoup
    and compares visible text to `href`. This matches common phishing
    patterns where the displayed URL is benign but the link points
    elsewhere.
    """
    body_bytes = body.encode('utf-8') if isinstance(body, str) else body
    decoded = quopri.decodestring(body_bytes).decode('utf-8', 'ignore')
    soup = BeautifulSoup(decoded, 'html.parser')
    score = 0
    for link in soup.find_all('a'):
        href = link.get('href', '').lower().strip('/')
        text = link.get_text().lower().strip('/')
        # If the visible text contains a URL but the href differs,
        # consider it suspicious.
        if 'http' in text and href != text and href not in text:
            score += config.WEIGHT_HIDDEN_LINK_MISMATCH
    return min(score, config.MAX_HIDDEN_LINK_CAP)

def check_auth(msg):
    """Score SPF/DKIM/DMARC findings based on headers.

    Performs simple string checks against common authentication headers
    and returns an additive penalty defined in `config`.
    """
    auth = str(msg.get('Authentication-Results', '')).lower()
    spf_hdr = str(msg.get('Received-SPF', '')).lower()

    s = config.AUTH_FAIL if ('spf=fail' in auth or 'fail' in spf_hdr) else (config.AUTH_PASS if 'pass' in auth else config.AUTH_SPF_SOFT_MISSING)
    d = config.AUTH_FAIL if 'dkim=fail' in auth else (config.AUTH_PASS if 'dkim=' in auth else config.AUTH_MISSING)
    dm = config.AUTH_FAIL if 'dmarc=fail' in auth else (config.AUTH_PASS if 'dmarc=' in auth else config.AUTH_MISSING)

    return s + d + dm

def check_sender_mismatch(msg):
    """Flag when `Reply-To` differs from `From` (possible spoofing).

    Attackers sometimes set a different `Reply-To` to divert
    responses; this heuristic penalizes that case.
    """
    from_addr = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    return config.WEIGHT_SENDER_MISMATCH if reply_to and reply_to not in from_addr else 0

def check_link_density(body):
    """Return a penalty when the number of links exceeds a threshold.

    This function counts http/https URLs and returns
    `config.WEIGHT_HIGH_LINK_DENSITY` if the count is above
    `config.MAX_LINK_THRESHOLD`, otherwise 0.
    """
    urls = re.findall(r'https?://[^\s<>"]+', body)
    return config.WEIGHT_HIGH_LINK_DENSITY if len(urls) > config.MAX_LINK_THRESHOLD else 0


def check_shortener_links(body):
    """Detect presence of URL shortener domains and return a penalty.

    Scans all http/https URLs in `body` and returns
    `config.WEIGHT_SHORTENER_DETECTED` if any known shortener domain
    appears in a URL.
    """
    urls = re.findall(r"https?://[^\s<>' \"]+", body)
    return config.WEIGHT_SHORTENER_DETECTED if any(bad in u for u in urls for bad in config.SHORTENER_DOMAINS) else 0

def analyze_email_risk(raw_data):
    """Run all detectors and return a normalized risk report.

    The returned dict contains a bounded `score` and an `alerts` list
    with the names of checks that contributed positively to the score.
    """
    msg = parse_eml(raw_data)
    body = extract_body(msg)

    checks = {
        "Header Injection": check_header_injection(raw_data),
        "Attachment Risk": check_attachments_deep(msg),
        "Hidden Link": check_hidden_links(body),
        "Auth (SPF/DKIM/DMARC)": check_auth(msg),
        "Sender Mismatch": check_sender_mismatch(msg),
        "Link Density": check_link_density(body),
        "Shortener Detected": check_shortener_links(body)
    }

    total = min(max(sum(checks.values()), config.MIN_SCORE), config.MAX_SCORE)
    return {
        "score": total,
        "alerts": [name for name, score in checks.items() if score > 0]
    }
