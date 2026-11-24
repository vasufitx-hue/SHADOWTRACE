# SHADOWTRACE
### Rule-Based Scam Detection & Cyber Threat Intelligence Platform

SHADOWTRACE is a cybersecurity intelligence platform designed to analyze suspicious messages and URLs, identify potential scam indicators, calculate risk scores, and generate structured intelligence reports.

The project focuses on helping users understand suspicious digital communications through explainable, rule-based analysis.

---

## 1. Project Overview

Online scams frequently use urgency, impersonation, suspicious links, and requests for sensitive information to manipulate users.

SHADOWTRACE analyzes submitted messages and extracts useful security indicators to help identify potential phishing and scam attempts.

### Core Capabilities

- Suspicious message analysis
- Scam keyword detection
- URL extraction and security analysis
- Scam DNA indicator extraction
- Rule-based risk scoring
- Risk classification
- Explainable risk reasons
- JSON intelligence report generation
- Web-based analysis dashboard

---

## 2. System Architecture

SHADOWTRACE uses a frontend-backend architecture.

```text
                 USER
                   |
                   v
          REACT FRONTEND
           (Vite Dashboard)
                   |
                   v
             FASTAPI
             REST API
                   |
                   v
        PYTHON INTELLIGENCE ENGINE
                   |
          +--------+--------+
          |        |        |
          v        v        v
        TEXT     URL     SCAM DNA
      ANALYZER ANALYZER  ANALYZER
          |        |        |
          +--------+--------+
                   |
                   v
              RISK ENGINE
                   |
                   v
          INTELLIGENCE REPORT
                   |
                   v
             JSON EXPORT
```

---

## 3. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React |
| Development Server | Vite |
| Backend | Python |
| API Framework | FastAPI |
| API Communication | REST / JSON |
| Testing | Pytest |
| Report Format | JSON |
| Development Environment | VS Code |

---

## 4. Intelligence Engine

### Text Analyzer
- Normalizes submitted text.
- Detects suspicious keywords.
- Extracts URLs from messages.

### URL Analyzer
- Examines suspicious URL characteristics.
- Detects IP-based URLs.
- Identifies URL shorteners.
- Detects unencrypted HTTP connections.
- Checks suspicious URL paths and punycode indicators.

### Scam DNA
- Extracts scam-related indicators.
- Classifies potential scam patterns.
- Generates scam fingerprints.
- Supports comparison of scam fingerprints.

### Risk Engine
- Calculates a rule-based risk score.
- Assigns a risk classification.
- Explains the reasons behind the assessment.
- Applies score validation and boundaries.

**Important:** Risk scores are heuristic assessments, not statistically calibrated probabilities or guaranteed predictions.

---

## 5. Installation and Setup

### Prerequisites

- Python
- Node.js and npm
- Visual Studio Code

### Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SHADOWTRACE
```

### Backend setup

Create and activate a virtual environment.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install backend dependencies:

```powershell
python -m pip install "fastapi[standard]" pytest
```

Start the backend:

```powershell
python -m uvicorn backend.app.api:app
```

Backend URL:

`http://127.0.0.1:8000/`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

### Frontend setup

Open a second terminal.

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

Frontend URL:

`http://localhost:3000/`

Keep both development servers running while using the application.

---

## 6. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Backend health check |
| POST | `/analyze` | Analyze a submitted message |
| GET | `/docs` | Interactive API documentation |

Example analysis request:

```json
{
  "message": "URGENT! Your bank account is blocked. Verify your KYC immediately."
}
```

---

## 7. Testing

SHADOWTRACE uses Pytest for automated backend testing.

Run the complete test suite:

```powershell
python -m pytest -v
```

Latest recorded test result during development:

**40 tests passed.**

Test coverage includes:
- API validation
- Report generation
- Risk classification
- Scam DNA extraction
-