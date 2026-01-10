# Prototype Pollution Scanner

**ProtoScan** (`protoscan`) is a Python CLI that analyzes JavaScript/TypeScript projects for prototype pollution risk. It walks the repo, identifies user-controlled sources, tracks them to unsafe sinks/gadgets, checks dependencies for known CVEs, and outputs findings in JSON/SARIF/HTML/CSV (plus a human summary).

## Setup

```bash
git clone https://github.com/Bhanunamikaze/ProtoScan.git
cd ProtoScan
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

```

## CLI Usage

```bash
protoscan scan --project path/to/app [options]
```

Common options:

- `--format json|sarif|html|csv|human` – emit one or more report formats (repeat the flag).
- `--output <format> <file>` – write a specific format to disk instead of stdout (e.g., `--output sarif report.sarif`).
- `--severity <low|medium|high|critical>` – minimum severity to include (defaults to `medium`).
- `--project <path>` – root directory to scan (defaults to current working directory).
- `--runtime-hint <hint>` – provide runtime/framework hints if autodetection needs help (repeatable).
- `--config <file>` – load overrides from `.protoscanrc.json`-style config.
- `--bundle <zip>` – package JSON/SARIF/HTML/CSV outputs into a zip archive (useful for CI artifacts).

Example (JSON on stdout + SARIF/HTML/CSV saved to files):

```bash
protoscan scan \
  --project my-app \
  --format json \
  --format sarif --output sarif my-app.sarif \
  --format html --output html my-app.html \
  --format csv --output csv my-app.csv
```

## What the Scanner Detects
- Runtime & framework indicators (Node.js, browser bundles, Deno, Bun, etc.) with per-subproject details so multi-repo workspaces show which path triggered each runtime hint.
- Dependency CVEs (lodash, qs, minimist, merge, deep-extend, …).
- Per-project dependency context (findings include a `project` field when multiple manifests are scanned).
- User-controlled sources (HTTP/CLI/env/URL/localStorage/WebSocket/JSON input).
- Unsafe sinks (Object.assign, spread, qs.parse, JSON revivers, dynamic property writes, merge loops, constructor prototype writes).
- Gadgets that turn pollution into impact (child_process, vm, template engines, filesystem).
- Flow chains describing source→sink→gadget paths with severity, route context, validation hints, and payload snippets.

## How It Works
1. **Project & dependency discovery** – ProtoScan walks the repo (JS/TS extensions only), parses every `package*.json`/lockfile, and enriches findings with dependency context plus GitHub/OSV advisories.
2. **Runtime & source detection** – Tree-sitter parsers identify runtime hints (Node, browser, Deno, Bun) and tag every user-controlled source (Express/Fastify handlers, CLI argv, env/config readers, URL/localStorage, WebSocket handlers, etc.).
3. **AST-based sink & gadget detection** – The same AST walks look for prototype-pollution sinks (Object.assign, lodash.merge/defaults/set, qs/ini/toml parsers, unsafe loops, constructor prototype writers) and gadgets (child_process/vm/template/fs/HTTP clients).
4. **Taint graph construction** – A lightweight alias graph links identifiers inside each file (assignments, destructuring, spreads, class fields, implicit arrow-function returns). Imports/exports build a project-level call graph so taint flows across modules.
5. **Chain assembly & severity** – Sources, sinks, and gadgets are matched by shared aliases/routes. Chains include reachability (route/middleware metadata), schema-validation checks, auth hints, payload templates per sink, and gadget impact text. Severity is downgraded when auth or strict validation is present; otherwise, critical/high severities surface by default.
6. **Reporting** – Chains plus standalone findings feed all reporters (JSON/SARIF/HTML/CSV/human). SARIF contains structured metadata for code-scanning portals, HTML/CSV provide dashboards, and CLI stdout can emit multiple formats simultaneously.

## Sample Scans
Use the bundled fixtures to see realistic findings:

```bash
# server-side vulnerable app
PYTHONPATH=src python -m protoscan.cli scan --project tests/fixtures/vuln_app --format html --output html vuln-report.html

# browser bundle example
PYTHONPATH=src python -m protoscan.cli scan --project tests/fixtures/browser_bundle --format json

# bundle all report formats
PYTHONPATH=src python -m protoscan.cli scan --project tests/fixtures/vuln_app --bundle reports.zip
```

Pre-generated reports for tests live under `tests/data/sample-report.*` (JSON/SARIF/HTML/CSV/human) and help validate formatting changes.

## Testing

```bash
python -m unittest
```

CI (GitHub Actions) runs the same suite plus the vulnerable fixture scan (`.github/workflows/ci.yml`).
Unit tests cover the detector modules, reporting snapshots, and the bundled fixtures so regressions are caught early.

- To publish reports from CI, you can bundle them and upload as an artifact. Example (GitHub Actions):

  ```yaml
  - name: Scan repo
    run: PYTHONPATH=src python -m protoscan.cli scan --project . --bundle reports.zip

  - name: Upload reports
    uses: actions/upload-artifact@v4
    with:
      name: protoscan-reports
      path: reports.zip
  ```

## Fixtures & Outputs

- `tests/fixtures/vuln_app` – deliberately vulnerable Node.js app (HTTP/CLI/WS sources + unsafe sinks/gadgets).
- `tests/fixtures/browser_bundle` – browser bundle demonstrating DOM/URL/localStorage sources.
- Pre-generated sample reports live under `tests/data/sample-report.*`:
  - `sample-report.json` – full JSON object with dependency findings, sources/sinks, gadgets, and flow chains.
  - `sample-report.sarif` – SARIF v2.1 listing each chain (with descriptions/validation/payload metadata).
  - `sample-report.html` – single-page dashboard view (severity table + download links).
  - `sample-report.csv` – tabular summary (one row per chain).
  - `sample-report.txt` – human-readable summary for quick terminal review.

Run the fixtures yourself to regenerate these outputs (see “Sample Scans”).

## License

ProtoScan is distributed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International license. See the `LICENSE` file in the repository root for the full terms.

## Disclaimer
This project is for educational and defensive security research only. Results come from static analysis heuristics; always validate findings in a safe environment before attempting exploitation or remediation in production systems.
