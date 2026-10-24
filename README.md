# Security Assessment Platform

**Automated Network Vulnerability Assessment and Security Reporting Platform** — a university Computer Security prototype.

A Python + Streamlit app that lets a user pick an **authorised** target, run network discovery (Nmap), vulnerability and web checks (Nuclei, Nikto) and a local host audit (Lynis), combine everything into one finding format, add a machine-learning *priority* (scikit-learn, synthetic data), show remediation advice, and export CSV/HTML reports.

> ⚠️ Only scan systems you own or have written permission to test. The app starts in **sample mode** (mock data, no tools run). Real scans require switching sample mode off *and* ticking the authorisation box.

This is a student prototype, not a commercial scanner.

---

## Contents
1. [Quick start](#1-quick-start)
2. [External tools & platform support](#2-external-tools--platform-support)
3. [How it fits together](#3-how-it-fits-together)
4. [The shared finding format](#4-the-shared-finding-format)
5. [Function contracts](#5-function-contracts)
6. [Member Implementation Guide](#6-member-implementation-guide)
7. [AI assistant prompt template](#7-ai-assistant-prompt-template)
8. [GitHub collaboration rules](#8-github-collaboration-rules)
9. [Testing](#9-testing)
10. [Integration checklist](#10-integration-checklist)
11. [Machine learning notes](#11-machine-learning-notes)
12. [Design decisions & known limitations](#12-design-decisions--known-limitations)

---

## 1. Quick start

Requires **Python 3.10 – 3.13**. Run everything from the repository root.

**macOS / Linux**
```bash
git clone https://github.com/<your-account>/security-assessment-platform.git
cd security-assessment-platform
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                 # run the tests
streamlit run app.py                # open http://localhost:8501
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/<your-account>/security-assessment-platform.git
cd security-assessment-platform
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
python -m pytest -q
streamlit run app.py
```

In the dashboard: keep **Sample mode** on, press **Start assessment**, look through the findings, then **Generate CSV and HTML reports**. Reports are saved in `reports/` (ignored by Git) and offered as downloads.

To recreate the synthetic dataset: `python -m modules.ml_classifier`

---

## 2. External tools & platform support

`pip install` installs **only Python packages**. The scanners are separate programs. Sample mode works without any of them.

| Tool | Used by | macOS (Homebrew) | Linux (Debian/Ubuntu/Kali) | Windows |
|---|---|---|---|---|
| Nmap | `target_scanner.py` | `brew install nmap` | `sudo apt install nmap` | Installer from nmap.org (includes Npcap) |
| Nuclei | `vulnerability_scanner.py` | `brew install nuclei` | Release binary from GitHub (projectdiscovery/nuclei) | Release binary from GitHub |
| Nikto | `vulnerability_scanner.py` | `brew install nikto` | `sudo apt install nikto` | Needs Perl; easiest via **WSL** |
| Lynis | `host_auditor.py` | `brew install lynis` | `sudo apt install lynis` | **Not supported** natively; use WSL |

After installing, check with `nmap --version`, `nuclei -version`, `nikto -Version`, `lynis --version`. Tools must be on your `PATH`.

**Platform summary**
- **macOS / Linux:** everything works. Lynis without `sudo` skips some tests (results are still useful).
- **Windows:** dashboard, sample mode, ML, reports, Nmap and Nuclei work. Nikto and Lynis need WSL; the app shows a clear message if they are missing.
- Nmap uses `-sT` (TCP connect scan), which does **not** need root/admin.
- **Lynis audits the machine it runs on** (your laptop), not a remote host. It is not a remote scanner — the "Host audit" option always refers to *this machine*, whatever target you type.

---

## 3. How it fits together

```
app.py (Streamlit UI)  ── run_assessment(target, checks, sample_mode)
   │
   ├─ target_scanner.scan_target()          ─┐
   ├─ vulnerability_scanner.scan_vulnerabilities() ├─► list[dict]  (schemas.py format)
   ├─ host_auditor.audit_host()             ─┘
   │
   ├─ ml_classifier.classify_findings()     adds "ml_priority"
   ├─ remediation.add_recommendations()     adds "recommendation" (via recommend_fix)
   └─ reporting.generate_csv_report() / generate_html_report()
```

```
security-assessment-platform/
├── app.py                     Streamlit dashboard + run_assessment() pipeline
├── config.py                  shared settings (paths, timeouts, limits, seed)
├── schemas.py                 THE shared finding format
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── __init__.py
│   ├── tool_utils.py          safe subprocess helper (run_tool, tool_available)
│   ├── target_scanner.py      validate_target, scan_target (Nmap)
│   ├── vulnerability_scanner.py  scan_vulnerabilities (Nuclei/Nikto), normalize_findings
│   ├── host_auditor.py        audit_host (Lynis)
│   ├── ml_classifier.py       load_dataset, train_model, classify_findings
│   ├── remediation.py         recommend_fix, apply_fix (disabled)
│   └── reporting.py           generate_csv_report, generate_html_report
├── data/
│   └── synthetic_findings.csv 300-row synthetic training set
├── reports/
│   └── .gitkeep               generated reports land here (git-ignored)
└── tests/
    ├── __init__.py
    └── test_interfaces.py     interface tests (no real scans)
```

**One addition to the agreed structure:** `modules/tool_utils.py`. Three modules run external programs; putting the safe `subprocess` code (argument lists, no shell, timeouts, missing-tool errors) in one tested place stops each member writing it differently.

**Error contract (all modules):**
- `ValueError` → bad user input (e.g. invalid target)
- `RuntimeError` → tool missing / failed / timed out / unsupported OS
- `NotImplementedError` (a subclass of `RuntimeError`) → that part isn't written yet

The dashboard catches these, shows the message, and keeps going with the other modules.

---

## 4. The shared finding format

Defined in `schemas.py`. **Every** module passes findings as `list[dict]`, each dict built with `schemas.new_finding(...)` or `schemas.Finding(...).to_dict()`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | str | 8-char hex, auto | unique per finding |
| `target` | str | required | host/IP the finding is about |
| `source` | str | required | `"nmap"`, `"nuclei"`, `"nikto"`, `"lynis"`, … Sample data **must** use `sample_source("nmap")` → `"nmap (sample)"` |
| `title` | str | required | short name |
| `severity` | str | `"Info"` | exactly one of `Critical`, `High`, `Medium`, `Low`, `Info` |
| `description` | str | `""` | plain-language explanation |
| `evidence` | str | `""` | port, URL, raw line, test ID… |
| `ml_priority` | str | `""` | `""` (unclassified) or `P1` / `P2` / `P3` — set only by `ml_classifier` |
| `recommendation` | str | `""` | set by `remediation` |

Helpers: `normalize_severity("warning") → "Medium"`, `is_sample(finding)`, `validate_finding(dict)`, `sort_by_severity(list)`, constants `SEVERITIES`, `SEVERITY_SCORES`, `ML_PRIORITIES`, `FINDING_FIELDS`.

Rule: modules **add** fields (`ml_priority`, `recommendation`); they never delete or overwrite `title`, `severity`, `description` or `evidence`.

---

## 5. Function contracts

| Function | Input | Output | Status |
|---|---|---|---|
| `target_scanner.validate_target(target: str) -> bool` | user text | `True`/`False`, never raises | ✅ done |
| `target_scanner.scan_target(target: str, sample_mode: bool = False) -> list[dict]` | target | one finding per open port | sample ✅ / real 🔧 M1 |
| `vulnerability_scanner.scan_vulnerabilities(target: str, sample_mode: bool = False) -> list[dict]` | target | Nuclei + Nikto findings | sample ✅ / real 🔧 M2 |
| `vulnerability_scanner.normalize_findings(raw_results: list[dict], target: str, source: str) -> list[dict]` | raw tool rows | findings | generic ✅ / tool tweaks 🔧 M2 |
| `host_auditor.audit_host(sample_mode: bool = False) -> list[dict]` | — | Lynis findings for this machine | sample ✅ / real 🔧 M3 |
| `ml_classifier.load_dataset() -> tuple` | — | `(X: DataFrame, y: Series)` | ✅ done |
| `ml_classifier.train_model() -> object` | — | fitted estimator with `.evaluation_` dict | 🔧 M4 |
| `ml_classifier.classify_findings(findings: list[dict]) -> list[dict]` | findings | copies with `ml_priority` | empty-list ✅ / rest 🔧 M4 |
| `remediation.recommend_fix(finding: dict) -> str` | finding | non-empty advice | baseline ✅ / more rules 🔧 M3 |
| `remediation.apply_fix(finding: dict, confirmed: bool = False) -> dict` | finding | `{"finding_id", "applied": False, "message", "recommendation"}` | ✅ disabled by design |
| `reporting.generate_csv_report(findings: list[dict], output_path: str) -> str` | findings, path | path written | baseline ✅ / polish 🔧 M5 |
| `reporting.generate_html_report(findings: list[dict], output_path: str) -> str` | findings, path | path written | baseline ✅ / polish 🔧 M5 |

Every function has a docstring and `TODO (Member N)` comments with the exact steps, tool arguments and return format.

---

## 6. Member Implementation Guide

Five members, five areas. Every member also: keeps the tests green, adds tests for their own functions, and supplies 1–2 slides about their part.

| Member | Area | Files you own | Main TODOs |
|---|---|---|---|
| **Member 1** | Network discovery | `modules/target_scanner.py` | real Nmap run, `_parse_nmap_xml()`, risky-service severity rules |
| **Member 2** | Vulnerability & web scanning | `modules/vulnerability_scanner.py` | Nuclei + Nikto runs, JSON parsing, skip-one-tool behaviour |
| **Member 3** | Host audit & remediation | `modules/host_auditor.py`, `modules/remediation.py` | Lynis run, `_parse_lynis_report()`, recommendation rules for every finding type |
| **Member 4** | Machine learning | `modules/ml_classifier.py`, `data/synthetic_findings.csv` | `train_model()`, `classify_findings()`, evaluation shown in the app, model explanation for slides |
| **Member 5** | Dashboard & reporting | `app.py`, `modules/reporting.py` | UI polish, show ML accuracy, HTML report summary/styling, optional PDF, final integration & demo script |

**Files nobody changes alone:** `schemas.py`, `config.py`, `requirements.txt`, `modules/tool_utils.py`, existing tests in `tests/test_interfaces.py`. Need a change? Open an issue / message the group, agree, then one person makes it in its own PR.

### Member 1 — `modules/target_scanner.py`
- **Functions:** `scan_target()` real mode, `_parse_nmap_xml()`. `validate_target()` is complete; you may tighten it but all its tests must still pass.
- **Receives:** a target string. **Returns:** `list[dict]` findings, one per open port (`source="nmap"`, usually `severity="Info"`), plus a "Host is up" finding for hosts with no open ports.
- **Rules:** use `run_tool([...])` from `tool_utils` (argument list, timeout built in); parse XML with the standard library `xml.etree.ElementTree`; no intrusive Nmap options.
- **Test alone:** `python -m pytest -q -k "target or sample"`; add a test that feeds a small saved Nmap XML string to `_parse_nmap_xml()`.

### Member 2 — `modules/vulnerability_scanner.py`
- **Functions:** `scan_vulnerabilities()` real mode, tool-specific tweaks in `normalize_findings()`.
- **Receives:** a target string. **Returns:** normalised findings from Nuclei and Nikto. If one tool is missing, include an Info finding saying it was skipped; if both are missing, raise `RuntimeError`.
- **Rules:** Nuclei with `-jsonl`, exclude `intrusive,dos,fuzz,brute-force` tags, rate limit from config; Nikto JSON output to a temp file, DoS tests excluded, max time from config.
- **Test alone:** `python -m pytest -q -k "normalize or vulnerab"`; add tests with saved Nuclei JSON lines and a Nikto JSON sample.

### Member 3 — `modules/host_auditor.py` + `modules/remediation.py`
- **Functions:** `audit_host()` real mode, `_parse_lynis_report()`; extend `RECOMMENDATION_RULES` in `remediation.py`.
- **Receives:** nothing (audits this machine) / a finding dict. **Returns:** Lynis findings (`warning`→Medium, `suggestion`→Low, hardening index as Info) / a recommendation string.
- **Rules:** Lynis only reads the system; write its report to `reports/lynis-report.dat` with `--report-file`. `apply_fix()` stays **disabled** — never turn scanner text into commands.
- **Test alone:** `python -m pytest -q -k "sample or recommend"`; add a test with a few saved `warning[]=` / `suggestion[]=` lines.

### Member 4 — `modules/ml_classifier.py`
- **Functions:** `train_model()`, `classify_findings()`. `load_dataset()`, `extract_features()` and the dataset generator are done.
- **Receives:** findings. **Returns:** copies with `ml_priority` in `P1/P2/P3`; nothing else changes.
- **Rules:** `DecisionTreeClassifier(max_depth=4, random_state=config.RANDOM_SEED)`, `train_test_split(..., stratify=y)`, store accuracy in `model.evaluation_`, cache the model in `_MODEL`. Training must stay under a second. If you change features, update `FEATURE_COLUMNS`, `extract_features()`, the generator **and** regenerate the CSV in the same PR.
- **Test alone:** `python -m pytest -q -k "classifier or dataset"` — the skipped test starts running once you implement `classify_findings()`.

### Member 5 — `app.py` + `modules/reporting.py`
- **Functions:** dashboard layout (`main()`), `run_assessment()` wiring, `generate_html_report()` polish, optional PDF.
- **Receives / returns:** see the contracts table. Reports must keep escaping all finding text with `html.escape`.
- **Rules:** only call module functions — never re-implement scanning or ML in `app.py`. Keep the dashboard working when a module raises `NotImplementedError`. Never add an "apply fix" button that runs anything.
- **Test alone:** `python -m pytest -q -k "report or pipeline"` and `streamlit run app.py` in sample mode.

### How to merge your work
```bash
git checkout main && git pull
git checkout -b feature/<area>           # e.g. feature/nmap-scanner
# ...work, commit small steps...
python -m pytest -q                      # must pass
git push -u origin feature/<area>
# open a Pull Request on GitHub → one teammate reviews → merge
```

---

## 7. AI assistant prompt template

Paste this into your AI coding assistant, filling in the brackets:

```text
You are helping me implement my part of a team project in an existing GitHub repository:
"security-assessment-platform" (Python, Streamlit, pandas, scikit-learn).

My role: [Member N - area]. My functions: [list from README section 6].
Files I may modify: [your files] and new tests at the bottom of tests/test_interfaces.py.

Before writing any code:
1. Read README.md (sections 4-6), schemas.py, config.py, modules/tool_utils.py and my module files.
2. Read the docstrings and "TODO (Member N)" comments in my functions - they are the spec.

Rules:
- Implement ONLY my assigned functions. Do not edit other members' modules, schemas.py,
  config.py, requirements.txt or tool_utils.py.
- Keep every function name, argument and return type exactly as written.
- Return findings only in the schemas.py format (use schemas.new_finding).
- Run external programs only through tool_utils.run_tool() with argument lists. No shell=True.
- Raise ValueError for bad input and RuntimeError for tool problems.
- Keep sample mode working and clearly labelled.
- Do not add new dependencies. Prefer the standard library. Ask me first if one is essential.
- Keep the code simple enough for a student to explain in a presentation.
- Never run real scans in tests; use saved sample output and mocks.

When done:
- Add tests for my functions using sample data only.
- Run: python -m pytest -q   (all tests must pass)
- Run: streamlit run app.py   in sample mode and confirm nothing broke.
- Summarise what you changed and any limitations.
```

---

## 8. GitHub collaboration rules

1. **`main`** always contains the integrated, working project. Nobody pushes directly to it.
2. Each member works on their own **feature branch** (`feature/<area>`).
3. Don't edit or overwrite other members' files. If you need something from another module, ask its owner.
4. **Shared files** (`schemas.py`, `config.py`, `requirements.txt`, `modules/tool_utils.py`, existing tests) change only after group agreement, in a separate PR.
5. Run `python -m pytest -q` before every push. A PR with failing tests is not merged.
6. Merge through **Pull Requests** with at least one teammate's review.
7. Integrate **small changes often** (aim for at least one merged PR per member per week), not one big merge before the deadline.
8. Before starting work each day: `git checkout main && git pull`, then `git merge main` into your branch.
9. Never commit secrets, real scan reports of other people's systems, or the `.venv/` folder (`.gitignore` covers these).

Recommended GitHub setting: *Settings → Branches → Add rule for `main` → Require a pull request before merging*.

---

## 9. Testing

```bash
python -m pytest -q                 # everything
python -m pytest -q -k target       # one area
```

`tests/test_interfaces.py` checks: target validation (accepts/rejects), finding fields and defaults, normalisation output, sample data labelling, empty lists in classifier and reports, remediation never applies fixes, small CSV/HTML reports (with HTML escaping), imports with no side effects, and a full sample-mode pipeline.

A test fixture **blocks `subprocess`** during tests, so a test that accidentally tries to run a real tool fails immediately. Use saved tool output and `unittest.mock` instead.

---

## 10. Integration checklist

Run after merging each member's PR (Member 5 leads, everyone checks their part):

- [ ] `pip install -r requirements.txt` works in a fresh virtual environment.
- [ ] `python -m pytest -q` passes (no new skips except unfinished areas).
- [ ] `streamlit run app.py` opens; sample mode shows findings from all three checks with no red errors.
- [ ] Every finding row has all 9 fields and a valid severity (the tests enforce this).
- [ ] Sample results show `(sample)` in the source column and the sample banner is visible.
- [ ] **M1:** real mode against `127.0.0.1` (or a lab VM you own) lists open ports.
- [ ] **M2:** real mode against a lab web server you own returns Nuclei/Nikto findings; uninstalling one tool shows a "skipped" Info finding instead of crashing.
- [ ] **M3:** real host audit on macOS/Linux returns Lynis warnings/suggestions; every finding has a specific recommendation (not just the generic one).
- [ ] **M4:** `ml_priority` column is filled (P1/P2/P3) and original severity/description are unchanged; accuracy shown in the app with the synthetic-data disclaimer.
- [ ] **M5:** CSV and HTML reports download and open; HTML shows the summary and escapes odd characters.
- [ ] Nothing scans or changes the system until **Start assessment** is pressed; no fix is ever applied.

---

## 11. Machine learning notes

- **Goal:** demonstrate how ML can *prioritise* findings (P1 fix now, P2 fix soon, P3 monitor). The scanners find the issues; the model does not detect vulnerabilities.
- **Data:** `data/synthetic_findings.csv`, 300 rows, generated with a fixed seed by `generate_synthetic_dataset()` in `ml_classifier.py`.
- **Features:** `severity_score` (0–4), `is_network`, `is_web`, `has_cve`, `exploit_keyword` (all 0/1 except severity).
- **Labelling rule:** `points = 2×severity + 2×has_cve + 3×exploit_keyword + is_network`; P1 if ≥ 9, P2 if ≥ 4, else P3; 5 % of labels randomly changed to mimic human disagreement.
- **Model:** a depth-4 decision tree (easy to draw and explain). A quick check gives roughly 0.9 accuracy on the held-out 25 %.
- **Honesty statement for the report and slides:** the model learns a rule we wrote ourselves on synthetic data, so its accuracy **does not** say anything about real-world vulnerability detection or prioritisation. Real use would need labelled data from real assessments.

---

## 12. Design decisions & known limitations

- **Plain functions + one dataclass.** `schemas.Finding` validates; everything else passes plain dicts.
- **No database, no auth, no Docker.** Results live in the Streamlit session; reports are files in `reports/`.
- **Remediation is recommendations only.** `apply_fix()` is a documented, disabled placeholder (`config.ALLOW_AUTO_REMEDIATION = False`). Turning untrusted scanner output into system changes is a command-injection risk and remote changes are out of scope. It never runs anything, even with `confirmed=True`.
- **Target limits.** Single IPs, hostnames or ranges up to `/24`. Validation checks format only; authorisation is confirmed by the user in the UI.
- **Lynis is local only** (see section 2).
- **PDF export is not included** — open the HTML report in a browser and use *Print → Save as PDF*. Member 5 may add a library later if the team agrees.
- **Real scanning modes are TODOs** for Members 1–3; until then they raise `NotImplementedError` and the dashboard shows a message.
- **ML training and classification are TODOs** for Member 4; until then findings show an empty ML priority.
