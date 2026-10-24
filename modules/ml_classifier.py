"""
modules/ml_classifier.py - simple ML prioritisation of findings (scikit-learn).

OWNER: Member 4 (Machine Learning)
Data format: schemas.py (reads findings, ADDS "ml_priority"; never removes fields)
Dataset: data/synthetic_findings.csv (path in config.SYNTHETIC_DATASET_PATH)

WHAT THE MODEL DOES (and does not do)
    The scanners find the issues. The model only suggests a remediation PRIORITY
    (P1 fix now / P2 fix soon / P3 monitor) from a few simple features.
    It is trained on SYNTHETIC data, so its accuracy says nothing about real-world
    vulnerability detection. Say this clearly in the presentation.

FEATURES (one row per finding; all integers) - defined in FEATURE_COLUMNS:
    severity_score   0-4   Info=0, Low=1, Medium=2, High=3, Critical=4
    is_network       0/1   came from a network tool (nmap/nuclei/nikto) vs local (lynis)
    is_web           0/1   came from a web tool (nuclei/nikto)
    has_cve          0/1   "CVE-" appears in title/description/evidence
    exploit_keyword  0/1   text mentions e.g. "remote code execution", "default credentials"
LABEL: priority in {"P1", "P2", "P3"}

Done by Foundation:   dataset generator + CSV, load_dataset(), extract_features().
TODO for Member 4:    train_model() and classify_findings().
"""

from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

import config
from schemas import ML_PRIORITIES, SAMPLE_SUFFIX, SEVERITY_SCORES

FEATURE_COLUMNS: list[str] = ["severity_score", "is_network", "is_web", "has_cve", "exploit_keyword"]
LABEL_COLUMN = "priority"

NETWORK_TOOLS = ("nmap", "nuclei", "nikto")
WEB_TOOLS = ("nuclei", "nikto")
EXPLOIT_KEYWORDS = (
    "remote code execution", "rce", "code execution", "command injection",
    "sql injection", "default credential", "default password", "unauthenticated",
    "path traversal", "authentication bypass", "clear text", "cleartext",
)

_MODEL = None  # cache for the trained model (Member 4 fills this in classify_findings)


# --------------------------------------------------------------------- done by Foundation
def extract_features(finding: dict) -> dict[str, int]:
    """Turn one finding dict into the feature dict used for training and prediction.

    Args:
        finding: dict in the schemas.py format (missing keys are tolerated).

    Returns:
        dict with exactly the keys in FEATURE_COLUMNS (int values).
    """
    tool = str(finding.get("source", "")).replace(SAMPLE_SUFFIX, "").strip().lower()
    text = " ".join(str(finding.get(k, "")) for k in ("title", "description", "evidence")).lower()
    return {
        "severity_score": SEVERITY_SCORES.get(finding.get("severity", "Info"), 0),
        "is_network": int(tool in NETWORK_TOOLS),
        "is_web": int(tool in WEB_TOOLS),
        "has_cve": int("cve-" in text),
        "exploit_keyword": int(any(k in text for k in EXPLOIT_KEYWORDS)),
    }


def load_dataset() -> tuple[pd.DataFrame, pd.Series]:
    """Load the synthetic dataset.

    Returns:
        (X, y): X = DataFrame with FEATURE_COLUMNS, y = Series of labels (P1/P2/P3).

    Raises:
        RuntimeError: dataset missing or missing required columns.
    """
    path = Path(config.SYNTHETIC_DATASET_PATH)
    if not path.exists():
        raise RuntimeError(
            f"Dataset not found at {path}. Recreate it with: python -m modules.ml_classifier"
        )
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_COLUMNS + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise RuntimeError(f"Dataset is missing columns: {missing}")
    return df[FEATURE_COLUMNS], df[LABEL_COLUMN]


def generate_synthetic_dataset(path: str | Path = config.SYNTHETIC_DATASET_PATH,
                               n_rows: int = config.SYNTHETIC_ROWS) -> Path:
    """Create the small, reproducible synthetic dataset (fixed seed).

    Labelling rule (documented so it can be explained in the presentation):
        points = 2*severity_score + 2*has_cve + 3*exploit_keyword + is_network
        P1 if points >= 9, P2 if points >= 4, else P3
        then 5 % of labels are changed at random to simulate human disagreement.

    Returns:
        Path of the written CSV.
    """
    rng = random.Random(config.RANDOM_SEED)
    rows = []
    for _ in range(n_rows):
        tool = rng.choice(["nmap", "nuclei", "nikto", "lynis"])
        sev = rng.choices([0, 1, 2, 3, 4], weights=[25, 25, 25, 15, 10])[0]
        is_network = int(tool in NETWORK_TOOLS)
        is_web = int(tool in WEB_TOOLS)
        has_cve = int(is_web and rng.random() < 0.15 + 0.15 * sev)
        exploit = int(rng.random() < 0.05 + 0.12 * sev)
        points = 2 * sev + 2 * has_cve + 3 * exploit + is_network
        label = "P1" if points >= 9 else "P2" if points >= 4 else "P3"
        if rng.random() < 0.05:
            label = rng.choice(ML_PRIORITIES)
        rows.append([sev, is_network, is_web, has_cve, exploit, label])
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows, columns=FEATURE_COLUMNS + [LABEL_COLUMN]).to_csv(out, index=False)
    return out


# --------------------------------------------------------------------- TODO (Member 4)
def train_model() -> object:
    """Train a simple classifier on the synthetic dataset.

    Returns:
        A fitted scikit-learn estimator with an extra attribute
            model.evaluation_ = {"accuracy": float, "train_rows": int, "test_rows": int}

    Raises:
        RuntimeError: dataset missing/invalid (from load_dataset()).

    TODO (Member 4):
        X, y = load_dataset()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=config.ML_TEST_SIZE, random_state=config.RANDOM_SEED, stratify=y)
        model = DecisionTreeClassifier(max_depth=4, random_state=config.RANDOM_SEED)
            (a small decision tree is easy to explain; you may print/plot it for the slides)
        model.fit(X_train, y_train)
        model.evaluation_ = {"accuracy": accuracy_score(y_test, model.predict(X_test)), ...}
        return model
        Training must stay fast (< 1 s). No saving to disk is required.
    """
    raise NotImplementedError("train_model is not implemented yet (Member 4).")


def classify_findings(findings: list[dict]) -> list[dict]:
    """Add an ML priority to each finding.

    Args:
        findings: list of finding dicts (schemas.py format).

    Returns:
        NEW list of copies of the findings, each with "ml_priority" set to one of
        schemas.ML_PRIORITIES. All other fields are unchanged.
        Empty input -> empty list.

    Raises:
        RuntimeError: model could not be trained (the dashboard then shows the
                      findings without ML priority).

    TODO (Member 4):
        global _MODEL
        if _MODEL is None: _MODEL = train_model()
        X = pd.DataFrame([extract_features(f) for f in findings], columns=FEATURE_COLUMNS)
        predictions = _MODEL.predict(X)
        return [{**f, "ml_priority": str(p)} for f, p in zip(findings, predictions)]
    """
    if not findings:
        return []
    raise NotImplementedError("classify_findings is not implemented yet (Member 4).")


if __name__ == "__main__":
    # python -m modules.ml_classifier  -> regenerate data/synthetic_findings.csv
    print(f"Wrote {generate_synthetic_dataset()}")
