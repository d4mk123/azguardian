# Azure NSG CIS Compliance Analyzer — Project Plan

**Scope:** Solo portfolio project. Ingests Azure Network Security Group (NSG) configs, checks them against the CIS Microsoft Azure Foundations Benchmark, runs ML-based anomaly detection on the ruleset, and produces a report with an LLM-written narrative + remediation guidance.

**Timeline:** 21 days, solo. Assumes \~4–6 focused hours/day — adjust pacing to your actual availability, the *order* matters more than the exact day count. The extra week (vs. the original 14-day version) goes toward deeper testing, a live Azure validation pass, and a proper dashboard instead of rushing them.

\---

## 1\. Tools You'll Need

**Everything below is free.** No paid API keys required anywhere in this build — the LLM layer runs locally via Ollama, and the recommended test-data path (static JSON fixtures) needs zero Azure account or spend.

### Core stack

* **Python 3.11+** — main language
* **Azure SDK for Python**: `azure-identity`, `azure-mgmt-network`, `azure-mgmt-resource` — for live NSG ingestion
* **Azure CLI (`az`)** — for testing, exporting sample data (`az network nsg list -o json`), and quick manual verification
* **Pydantic** — typed data models for NSGs/rules (catches malformed data early, gives you clean JSON for the LLM step)
* **PyYAML** — encode CIS rule checks as declarative rule definitions

### ML / anomaly detection

* **pandas / numpy** — feature engineering
* **scikit-learn** — Isolation Forest (or DBSCAN) for outlier rule detection

### AI narrative layer — 100% free, local

* **Ollama** (free, open source) running a local open-weight model (**Llama 3.2**, **Mistral 7B**, or **Phi-3.5** for lower-spec machines) — turns structured findings JSON into an executive summary and plain-English remediation guidance. No API key, no token costs, no data leaves your machine. Integrate via Ollama's local REST API or the `ollama` Python package.

### Reporting

* **Jinja2** — HTML templating
* **WeasyPrint** (or `reportlab`) — HTML → PDF
* **matplotlib** or **plotly** — pass/fail and severity charts

### CLI / interface

* **Typer** or **Click** — CLI entrypoint (`scan --subscription <id>` / `scan --input file.json`)
* **Streamlit** — interactive dashboard (findings table, severity chart, regenerate-summary button). With 3 weeks this is now a planned deliverable, not just a stretch goal.

### Infra for test data (pick one, don't need both)

* **Terraform** or **Bicep** — provision a throwaway Azure test environment with a few deliberately-misconfigured NSGs
* **Static JSON fixtures** — hand-crafted `az network nsg list` exports covering violation patterns (zero Azure cost, fully reproducible — recommended as your primary path, with live Azure as a bonus demo)

### Supporting tools

* **Git/GitHub** — version control, portfolio visibility
* **pytest** — unit tests for rule engine and ML module
* **ruff / black** — linting/formatting for a clean final repo
* **Excalidraw or draw.io** — architecture diagram for the README

\---

## 2\. Research To Do Before/While Building

1. **CIS Microsoft Azure Foundations Benchmark v3.0.0** (register free at cisecurity.org, download the PDF). Focus on:

   * The **Networking** section (NSG-specific controls: no unrestricted inbound on 22/3389/1433/5432/etc. from the internet, NSG flow logs enabled with adequate retention, NSG diagnostic logging)
   * Relevant cross-references in **Logging and Monitoring** (activity log alerts for NSG create/update/delete) since a complete "network security" report touches these too
   * Note each control's **Level 1 vs Level 2** designation — this feeds your severity/priority scoring
2. **Azure NSG rule model** — priority ordering, direction (inbound/outbound), the default rules every NSG ships with (`AllowVnetInBound`, `AllowAzureLoadBalancerInBound`, `DenyAllInBound`, etc. — don't flag these as findings), service tags (`Internet`, `VirtualNetwork`), and Application Security Groups (ASGs).
3. **Azure NSG Flow Logs v2 / Traffic Analytics** — needed for the logging-related controls.
4. **Classic firewall rule-anomaly taxonomy** (Al-Shaer \& Hamed): *shadowing, redundancy, generalization, correlation, irrelevance*. This is well-established network security research and will make your "ML anomaly detection" section much stronger than a generic outlier score — implement shadow/redundancy detection deterministically (rule-pair comparison), then layer statistical anomaly detection (Isolation Forest) on top for the "this rule doesn't look like the others" cases.
5. **Microsoft Defender for Cloud's regulatory compliance dashboard** — it already maps resources to CIS Azure controls. Useful as a **ground-truth check**: run your tool and Defender for Cloud against the same test environment and compare results — great validation story for your README/demo.
6. **Prompt design for grounded LLM report-writing** — the risk is hallucination (the model inventing findings or Azure commands that don't exist). Feed the LLM only your structured findings JSON + the actual CIS control text, and explicitly instruct it to comment only on provided findings.

\---

## 3\. Day-by-Day Plan

### Week 1 — Foundations

<b>~~Day 1 — Setup \& CIS research~~</b>

* Set up GitHub repo, Python venv, project skeleton
* Create CIS account, download the v3.0.0 PDF
* **Deliverable:** repo scaffold, PDF downloaded

<b>~~Day 2 — Deep-dive CIS research~~</b>

* Extract the \~15–20 NSG-relevant controls into a `control-mapping.yaml` (control ID, title, level, rationale, remediation)
* Read up on the Azure NSG rule model: priority, direction, default rules (`AllowVnetInBound`, `DenyAllInBound`, etc.), service tags, Application Security Groups
* **Deliverable:** `control-mapping.yaml`, notes on NSG rule semantics

**Day 3 — Data model \& ingestion**

* Define Pydantic models: `NetworkSecurityGroup`, `SecurityRule`, `Subnet`, `NicAssociation`
* Write `collector.py`: pulls NSGs via `azure-mgmt-network`, plus an offline loader for `az network nsg list -o json` exports
* **Deliverable:** working collector producing normalized JSON from either source

<b>~~Day 4 — Test data, part 1~~</b>

* Build 4–5 JSON fixtures covering violation patterns: open 22/3389 to `0.0.0.0/0`, missing flow logs, `Any/Any` rules, shadowed/redundant rule pairs, subnet with no NSG attached
* **Deliverable:** `/test-data` folder with core fixtures

<b>~~Day 5 — Test data, part 2 + buffer~~</b>

* Add a couple more edge-case fixtures (IPv6 rules, huge rulesets, malformed exports)
* Catch up on anything from Days 1–4 that ran long — this slack is intentional
* **Deliverable:** finalized fixture set

**Day 6 — CIS rule engine, part 1**

* Build `rule\\\\\\\\\\\\\\\_engine.py` with check functions for the first 8–10 controls (internet-exposed admin ports, `Any` source rules, missing deny-all, etc.)
* Each check returns: control ID, pass/fail/manual, affected resource, evidence, severity
* **Deliverable:** engine passing correctly against fixtures

**Day 7 — CIS rule engine, part 2 + severity scoring**

* Implement remaining \~10–15 checks (diagnostic logging, flow log retention, overly broad service tags, missing ASGs)
* Add a severity model (CIS Level 1/2 + internet exposure + port sensitivity → Critical/High/Medium/Low)
* Write pytest unit tests for every check
* **Deliverable:** full rule engine (\~20 controls), test suite green

\---

### Week 2 — Intelligence layer

**Day 8 — Anomaly detection, part 1 (deterministic)**

* Implement shadowing/redundancy/generalization detection as rule-pair comparisons (the Al-Shaer \& Hamed taxonomy)
* **Deliverable:** deterministic anomaly checks

**Day 9 — Anomaly detection, part 2 (features)**

* Build `features.py`: encode each rule as a feature vector (protocol, port bucket, priority, direction, source scope)
* **Deliverable:** feature dataframe from any fixture

**Day 10 — Anomaly detection, part 3 (ML)**

* Implement Isolation Forest over the feature vectors to flag statistically unusual rules
* Validate: does it catch the deliberately-planted weird rules in your fixtures?
* Add basic explainability (which features drove the anomaly score)
* **Deliverable:** `anomaly\\\\\\\\\\\\\\\_detector.py` + a short write-up of the approach/limitations (small-n caveat matters — be upfront about it)

**Day 11 — LLM narrative integration**

* Install Ollama, pull `llama3.2:3b` (fast, for dev) and `qwen2.5:7b-instruct` (quality, for final reports)
* Design the prompt: structured findings JSON + relevant CIS control text → executive summary, plain-English explanation per finding, remediation Azure CLI commands, prioritized action plan
* Explicitly constrain the model to only discuss provided findings — no invented facts
* **Deliverable:** `llm\\\\\\\\\\\\\\\_report\\\\\\\\\\\\\\\_writer.py`, tested against sample findings

**Day 12 — Report generation, part 1**

* Jinja2 HTML template: exec summary, findings table, anomaly section, remediation appendix with exact `az network nsg rule` fix commands
* **Deliverable:** HTML report rendering correctly from a fixture

**Day 13 — Report generation, part 2**

* HTML → PDF (WeasyPrint), add pass/fail and severity charts (matplotlib/plotly)
* **Deliverable:** first full end-to-end `report.pdf`

**Day 14 — Buffer / catch-up**

* No new features — fix whatever broke, revisit anything rushed in Week 2
* **Deliverable:** stable, working pipeline end-to-end (collector → engine → anomaly → LLM → report)

\---

### Week 3 — Interface, validation \& polish

**Day 15 — CLI**

* Wire everything behind a Typer CLI: `scan --subscription <id>` or `scan --input file.json` → `report.pdf`
* **Deliverable:** working CLI end-to-end

**Day 16 — Streamlit dashboard**

* Findings table, severity chart, "regenerate AI summary" button, upload-a-fixture flow
* **Deliverable:** working local dashboard

**Day 17 — Live Azure validation (optional but recommended with the extra week)**

* Provision a small live Azure test environment via Terraform with the same intentional misconfigurations as your fixtures
* Run your tool against it; also enable Microsoft Defender for Cloud's CIS regulatory compliance dashboard on the same environment and compare results
* **Deliverable:** a documented side-by-side of your tool's findings vs. Defender for Cloud's — strong validation evidence for your README/demo

**Day 18 — Testing \& edge cases**

* Cover empty NSGs, malformed JSON, large rulesets (perf), IPv6 rules, auth failures/throttling
* **Deliverable:** hardened codebase, updated test coverage

**Day 19 — Documentation**

* README with architecture diagram, setup, usage, screenshots
* Document limitations clearly (heuristic ML, not a certified compliance tool; CIS numbering may shift by version; requires Reader-only RBAC)
* Secrets via `.env`, never committed
* **Deliverable:** polished repo, LICENSE

**Day 20 — Demo prep**

* Run against 2–3 scenarios; show a before/after (fix a finding, rerun, improved score) — strong demo narrative
* Record a short demo GIF/video for the README
* Draft a one-pager/portfolio blurb describing the project
* **Deliverable:** demo assets

**Day 21 — Final review \& publish**

* Lint/format pass, clean commit history
* Push to GitHub, write your portfolio write-up
* List stretch goals for later: multi-cloud (AWS Security Groups, GCP firewall rules), CI/CD scheduled scans via GitHub Actions
* **Deliverable:** published, resume-ready repo

\---

## Fallback priority (if you run out of time)

1. Rule engine + report generation (core value — never cut this)
2. ML anomaly detection
3. LLM narrative polish
4. Streamlit dashboard
5. Live Azure validation pass (Day 17) — nice evidence, but the fixture-based tool works and demos fine without it

