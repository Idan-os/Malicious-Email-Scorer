# Scoring Limits
MAX_SCORE = 100
MIN_SCORE = 1

# Scoring Weights
WEIGHT_HEADER_INJECTION = 50
WEIGHT_DANGEROUS_EXT = 30
WEIGHT_DOUBLE_EXT = 30
WEIGHT_HIDDEN_LINK_MISMATCH = 15
WEIGHT_SENDER_MISMATCH = 20
WEIGHT_SHORTENER_DETECTED = 20
WEIGHT_HIGH_LINK_DENSITY = 10

# Auth Scores (Fail / Missing / Pass)
AUTH_FAIL = 20
AUTH_MISSING = 10
AUTH_SPF_SOFT_MISSING = 5
AUTH_PASS = 0

# Thresholds
MAX_LINK_THRESHOLD = 5
MAX_ATTACHMENT_RISK_CAP = 80
MAX_HIDDEN_LINK_CAP = 30

# Patterns & Lists
DANGEROUS_EXTENSIONS = ('.exe', '.bat', '.js', '.vbs', '.scr', '.msi')
SAFE_DOUBLE_EXT_SUFFIXES = ['pdf', 'docx', 'jpg', 'txt']
SHORTENER_DOMAINS = ('bit.ly', 'tinyurl', 't.co', 'goo.gl')
INJECTION_PATTERNS = ['<script', 'javascript:', 'onerror=', '<img']
