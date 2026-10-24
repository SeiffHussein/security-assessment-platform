"""
config.py - shared settings. Change values here, not inside modules.

No passwords, API keys or tokens belong in this file (or anywhere in the repo).
Paths are built from this file's location, so the app works when launched from
the repository root (and also from anywhere else).
"""

from pathlib import Path

APP_NAME = "Security Assessment Platform"
APP_VERSION = "0.1.0"

# ---------------------------------------------------------------- paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
SYNTHETIC_DATASET_PATH = DATA_DIR / "synthetic_findings.csv"

# ---------------------------------------------------------------- modes
# Sample mode returns clearly labelled mock results instead of running tools.
# The dashboard starts in sample mode; real scans must be switched on by the user.
SAMPLE_MODE_DEFAULT = True

# Automatic remediation is disabled by design (recommendations only).
# See modules/remediation.py before ever changing this.
ALLOW_AUTO_REMEDIATION = False

# ---------------------------------------------------------------- timeouts (seconds)
DEFAULT_TIMEOUT = 300
TOOL_TIMEOUTS = {
    "nmap": 300,
    "nuclei": 600,
    "nikto": 600,
    "lynis": 900,
}

# ---------------------------------------------------------------- scan limits
# Largest network range accepted by validate_target(): /24 = 256 addresses.
MIN_IPV4_PREFIX = 24
MIN_IPV6_PREFIX = 120
NMAP_TOP_PORTS = 100          # nmap --top-ports value
NUCLEI_RATE_LIMIT = 50        # requests per second
NIKTO_MAX_TIME = "300s"       # nikto -maxtime value

# ---------------------------------------------------------------- ML
RANDOM_SEED = 42
ML_TEST_SIZE = 0.25
SYNTHETIC_ROWS = 300
