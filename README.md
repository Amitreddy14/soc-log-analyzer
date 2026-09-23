# 🛡️ SOC Log Analyzer

**LLM-powered security log triage, alert correlation, and incident summarization.**

An intelligent pipeline that ingests multi-source security logs, normalizes them to Common Event Format (CEF), classifies severity using ML models, correlates related alerts into incidents, and generates human-readable incident reports via LLMs.

Think of it as an **AI SOC analyst that never sleeps.**

---

## The Problem

Security Operations Centers (SOCs) are drowning. Analysts face thousands of alerts per day from firewalls, IDS, endpoints, and servers. Over 95% are false positives or low-priority noise. Critical threats get buried, analysts burn out, and actual breaches slip through — not because tools fail, but because humans can't keep up with the volume.

## The Solution

This pipeline automates the three most time-consuming SOC tasks:

| Capability | Description | Status |
|---|---|---|
| **Ingestion & Normalization** | Multi-source log parsing (firewall, syslog, auth, IDS) → unified CEF schema | ✅ Complete |
| **Severity Classification** | ML-based triage (critical/high/medium/low/benign) with confidence scores | 🔨 Phase 2 |
| **Alert Correlation** | Groups related events into single incidents (e.g., scan → brute force → login) | 🔨 Phase 3 |
| **LLM Summarization** | Natural language incident reports with impact assessment and response actions | 🔨 Phase 4 |
| **Dashboard & API** | FastAPI backend + React frontend for real-time SOC visibility | 🔨 Phase 5 |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SOC Log Analyzer                       │
├─────────────┬─────────────┬──────────────┬─────────────────┤
│  Firewall   │   Syslog    │  Auth Logs   │  CICIDS/IDS     │
│  (PAN-OS)   │  (RFC 5424) │  (SSH/sudo)  │  (NetFlow)      │
└──────┬──────┴──────┬──────┴──────┬───────┴────────┬────────┘
       │             │             │                │
       ▼             ▼             ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│              Parser Layer (auto-detection)                   │
│         BaseParser → source-specific implementations         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           Normalization → CEF Unified Schema                 │
│        (Pydantic models, timestamp parsing, validation)      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   DuckDB Event Store                         │
│     (columnar storage, indexed queries, ingestion audit)     │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        [ML Triage] [Correlator] [LLM Summary]
         Phase 2      Phase 3     Phase 4
```

## Quick Start

```bash
# Clone
git clone https://github.com/yourusername/soc-log-analyzer.git
cd soc-log-analyzer

# Install
pip install -e ".[dev]"

# Generate sample data
soc-analyzer generate-samples

# Ingest sample logs
soc-analyzer ingest data/samples/

# View statistics
soc-analyzer stats
```

## Usage

### Ingest a single file
```bash
soc-analyzer ingest data/raw/Friday-WorkingHours.csv
```

### Ingest with explicit source type
```bash
soc-analyzer ingest /var/log/auth.log --source auth
```

### Ingest a directory
```bash
soc-analyzer ingest data/raw/ 
```

### Python API
```python
from soc_analyzer.ingestion import IngestionPipeline

pipeline = IngestionPipeline()
pipeline.start()

# Ingest with auto-detection
stats = pipeline.ingest_file("data/samples/firewall_traffic.csv")

# Query results
summary = pipeline.get_store_summary()
print(f"Total events: {summary['total_events']}")
print(f"By severity: {summary['by_severity']}")
print(f"Top source IPs: {summary['top_source_ips']}")

pipeline.stop()
```

## Supported Log Sources

| Source | Format | Auto-Detection Pattern |
|---|---|---|
| **CICIDS-2017** | CSV (78+ flow features) | `cicids`, `friday`, `monday`... |
| **Firewall** | PAN-OS CSV, iptables text | `firewall`, `iptables`, `panos` |
| **Syslog** | RFC 3164/5424 text | `syslog` |
| **Auth** | Linux auth.log | `auth`, `secure` |

Adding a new source: extend `BaseParser`, implement `parse_file()` and `normalize()`, register in `PARSER_REGISTRY`.

## Dataset

This project uses the [CICIDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset from the Canadian Institute for Cybersecurity — the industry benchmark for intrusion detection research.

**Attack types covered:** DDoS, DoS, Brute Force, Port Scan, Botnet, Infiltration, Web Attacks (XSS, SQL Injection), Heartbleed.

## Tech Stack

- **Python 3.10+** — core runtime
- **Pydantic v2** — schema validation and CEF data models
- **DuckDB** — columnar analytical storage (OLAP-optimized for log queries)
- **structlog** — structured JSON logging for observability
- **Click + Rich** — CLI with formatted output
- **pytest** — test suite with coverage

### Coming in later phases:
- **scikit-learn / PyTorch** — severity classification models
- **FastAPI** — REST API for dashboard
- **React + Recharts** — SOC dashboard frontend

## Testing

```bash
# Run full test suite with coverage
pytest

# Run specific test class
pytest tests/test_pipeline.py::TestAuthIngestion -v
```

## Project Structure

```
soc-log-analyzer/
├── src/soc_analyzer/
│   ├── models/           # Pydantic schemas (CEF-aligned)
│   ├── ingestion/        # Pipeline orchestrator
│   │   └── parsers/      # Per-source parsers
│   ├── storage/          # DuckDB backend
│   ├── utils/            # Logging, helpers
│   └── cli.py            # CLI entry point
├── tests/                # pytest test suite
├── scripts/              # Data generation, download helpers
├── data/
│   ├── raw/              # Full datasets (gitignored)
│   └── samples/          # Small test samples
└── docs/                 # Documentation
```

## License

MIT

## Author

**Amit** — [GitHub](https://github.com/yourusername)
