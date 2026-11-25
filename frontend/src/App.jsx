
import { useState, useEffect } from "react";

import {
  Shield,
  Search,
  Activity,
  AlertTriangle,
  Link,
  FileText,
  Lock,
  ShieldCheck,
  Loader2,
  Terminal,
  Download,
  Server,
  RefreshCw,
} from "lucide-react";

import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [apiStatus, setApiStatus] = useState("CHECKING");

  // Check whether the FastAPI backend is running.
  useEffect(() => {
    let active = true;

    async function checkBackend() {
      try {
        const response = await fetch(`${API_URL}/`);

        if (!response.ok) {
          throw new Error("Backend unavailable");
        }

        const data = await response.json();

        if (active) {
          setApiStatus(
            data.status === "online" ? "CONNECTED" : "OFFLINE"
          );
        }
      } catch {
        if (active) {
          setApiStatus("OFFLINE");
        }
      }
    }

    checkBackend();

    const interval = setInterval(checkBackend, 10000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // Send a suspicious message to the Python intelligence engine.
  async function analyzeMessage() {
    if (!message.trim()) {
      setError("Please enter a suspicious message first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Analysis request failed."
        );
      }

      setResult(data);
    } catch (err) {
      setError(
        err.message === "Failed to fetch"
          ? "Cannot connect to the backend. Make sure FastAPI is running on port 8000."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  // Export the complete investigation as a JSON file.
  function downloadReport() {
    if (!result) return;

    const report = {
      project: "SHADOWTRACE",
      report_generated_at: new Date().toISOString(),
      submitted_message: message,
      analysis: result,
    };

    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "shadowtrace_intelligence_report.json";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
  }

  // Extract information returned by the backend.
  const risk = result?.risk_analysis || {};
  const scamDNA = result?.scam_dna || {};
  const textAnalysis = result?.text_analysis || {};
  const urlAnalysis = result?.url_analysis || [];

  const riskScore = Number(risk.risk_score ?? 0);
  const riskLevel = risk.risk_level || "NOT ANALYZED";

  const riskClass =
    riskLevel.toLowerCase().includes("high")
      ? "high"
      : riskLevel.toLowerCase().includes("medium")
      ? "medium"
      : riskLevel.toLowerCase().includes("low")
      ? "low"
      : "unknown";

  const detectedKeywords =
    textAnalysis.detected_keywords || [];

  const detectedUrls =
    textAnalysis.detected_urls || [];

  const riskReasons =
    risk.risk_reasons || risk.reasons || [];

  const dnaIndicators =
    scamDNA.indicators || [];

  const scamCategory =
  scamDNA?.category ||
  scamDNA?.scam_category ||
  scamDNA?.fingerprint?.category ||
  textAnalysis?.category ||
  textAnalysis?.scam_category ||
  "Unknown";

  return (
    <div className="app">

      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-icon">
            <Shield size={25} />
          </div>

          <div>
            <h2>SHADOWTRACE</h2>
            <span>SCAM INTELLIGENCE</span>
          </div>
        </div>

        <div className="sidebar-section">
          <p className="sidebar-label">MAIN MENU</p>

          <div className="nav-item active">
            <Activity size={18} />
            <span>Dashboard</span>
          </div>

          <div className="nav-item">
            <Search size={18} />
            <span>Message Analysis</span>
          </div>

          <div className="nav-item">
            <Link size={18} />
            <span>URL Intelligence</span>
          </div>

          <div className="nav-item">
            <FileText size={18} />
            <span>Reports</span>
          </div>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-security">
            <Lock size={18} />

            <div>
              <strong>Security Engine</strong>
              <small>Rule-based detection</small>
            </div>
          </div>

          <p className="sidebar-version">
            SHADOWTRACE v1.0.0
          </p>
        </div>

      </aside>

      {/* MAIN CONTENT */}

      <main className="main-content">

        {/* TOPBAR */}

        <header className="topbar">

          <div>
            <p className="breadcrumb">
              SECURITY / DASHBOARD
            </p>

            <h1>Threat Intelligence Dashboard</h1>
          </div>

          <div className="system-status">
            <span
              className={`status-dot ${
                apiStatus === "CONNECTED"
                  ? "online"
                  : apiStatus === "OFFLINE"
                  ? "offline"
                  : ""
              }`}
            />

            <span>API: {apiStatus}</span>
          </div>

        </header>

        {/* WELCOME */}

        <section className="welcome-section">

          <div>
            <span className="section-tag">
              CYBERSECURITY INTELLIGENCE PLATFORM
            </span>

            <h2>
              Detect. Analyze. <span>Protect.</span>
            </h2>

            <p>
              Analyze suspicious messages and URLs using
              SHADOWTRACE's Python-based intelligence engine.
            </p>
          </div>

          <div className="welcome-icon">
            <ShieldCheck size={55} />
          </div>

        </section>

        {/* STATISTICS */}

        <section className="stats-grid">

          <div className="stat-card">
            <div className="stat-top">
              <span>ENGINE STATUS</span>
              <Activity size={19} />
            </div>

            <h3>
              {apiStatus === "CONNECTED"
                ? "ONLINE"
                : apiStatus}
            </h3>

            <small>Live FastAPI health check</small>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>RISK SCORE</span>
              <AlertTriangle size={19} />
            </div>

            <h3>
              {result ? `${riskScore}/100` : "--"}
            </h3>

            <small>Current investigation</small>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>SCAM CLASSIFICATION</span>
              <Shield size={19} />
            </div>

            <h3 className="category-stat">
              {result ? scamCategory : "NOT ANALYZED"}
            </h3>

            <small>Detected threat category</small>
          </div>

        </section>

        {/* ANALYZER */}

        <section className="panel analyzer-panel">

          <div className="panel-heading">

            <div>
              <div className="heading-icon">
                <Terminal size={19} />
              </div>

              <div>
                <h2>Message Intelligence Analyzer</h2>
                <p>Submit suspicious SMS, WhatsApp messages or text.</p>
              </div>
            </div>

            <span className="module-tag">
              PYTHON ENGINE
            </span>

          </div>

          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Paste a suspicious message here...

Example:
URGENT! Your SBI bank account is blocked.
Verify your KYC immediately at http://fake-bank.example/login"
            maxLength={5000}
          />

          <div className="input-footer">
            <span>{message.length}/5000 characters</span>

            <button
              className="analyze-button"
              onClick={analyzeMessage}
              disabled={loading || !message.trim()}
            >
              {loading ? (
                <>
                  <Loader2 className="spin" size={17} />
                  ANALYZING...
                </>
              ) : (
                <>
                  <Search size={17} />
                  ANALYZE MESSAGE
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="error-message">
              <AlertTriangle size={18} />
              {error}
            </div>
          )}

        </section>

        {/* RESULTS */}

        {result && (

          <section className="results-section">

            <div className="results-heading">

              <div>
                <span className="section-tag">
                  INVESTIGATION RESULTS
                </span>

                <h2>Threat Analysis Report</h2>
              </div>

              <div className="result-actions">
                <span className="module-tag">
                  ANALYSIS COMPLETE
                </span>

                <button
                  className="download-button"
                  onClick={downloadReport}
                >
                  <Download size={16} />
                  EXPORT JSON
                </button>
              </div>

            </div>

            {/* RISK CARD */}

            <div className="results-grid">

              <div className="panel risk-card">

                <div className="panel-heading">
                  <div>
                    <h3>Risk Assessment</h3>
                    <p>Rule-based heuristic assessment</p>
                  </div>

                  <AlertTriangle size={21} />
                </div>

                <div className="risk-score-container">

                  <div className={`risk-score ${riskClass}`}>
                    {riskScore}
                    <span>/100</span>
                  </div>

                  <div className={`risk-badge ${riskClass}`}>
                    {riskLevel}
                  </div>

                </div>

                <div className="risk-progress">
                  <div
                    className={`risk-progress-fill ${riskClass}`}
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(0, riskScore)
                      )}%`,
                    }}
                  />
                </div>

                <p className="risk-description">
                  Risk score is a heuristic assessment,
                  not a probability of fraud.
                </p>

              </div>

              {/* CLASSIFICATION */}

              <div className="panel classification-card">

                <div className="panel-heading">
                  <div>
                    <h3>Scam Classification</h3>
                    <p>Detected scam category</p>
                  </div>

                  <Shield size={21} />
                </div>

                <h2>{scamCategory}</h2>

                <span className="classification-note">
                  Rule-based classification
                </span>

              </div>

            </div>

            {/* DETECTION DETAILS */}

            <div className="results-grid details-grid">

              <div className="panel">

                <div className="panel-heading">
                  <div>
                    <h3>Detected Keywords</h3>
                    <p>Matching text indicators</p>
                  </div>

                  <Search size={19} />
                </div>

                <div className="tag-list">
                  {detectedKeywords.length > 0 ? (
                    detectedKeywords.map((keyword, index) => (
                      <span className="tag" key={index}>
                        {String(keyword)}
                      </span>
                    ))
                  ) : (
                    <p className="empty-state">
                      No keywords detected.
                    </p>
                  )}
                </div>

              </div>

              <div className="panel">

                <div className="panel-heading">
                  <div>
                    <h3>Detected URLs</h3>
                    <p>URLs found in submitted message</p>
                  </div>

                  <Link size={19} />
                </div>

                <div className="url-list">
                  {detectedUrls.length > 0 ? (
                    detectedUrls.map((url, index) => (
                      <div className="url-item" key={index}>
                        {String(url)}
                      </div>
                    ))
                  ) : (
                    <p className="empty-state">
                      No URLs detected.
                    </p>
                  )}
                </div>

              </div>

            </div>

            {/* RISK REASONS */}

            <div className="panel">

              <div className="panel-heading">
                <div>
                  <h3>Risk Factors</h3>
                  <p>Reasons contributing to the risk score</p>
                </div>

                <AlertTriangle size={19} />
              </div>

              <div className="reason-list">
                {riskReasons.length > 0 ? (
                  riskReasons.map((reason, index) => (
                    <div className="reason-item" key={index}>
                      <AlertTriangle size={16} />
                      <span>
                        {typeof reason === "string"
                          ? reason
                          : JSON.stringify(reason)}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="empty-state">
                    No additional risk reasons returned.
                  </p>
                )}
              </div>

            </div>

            {/* SCAM DNA */}

            <div className="panel">

              <div className="panel-heading">
                <div>
                  <h3>Scam DNA Intelligence</h3>
                  <p>Behavioral indicators detected in the message</p>
                </div>

                <ShieldCheck size={19} />
              </div>

              <div className="tag-list">
                {dnaIndicators.length > 0 ? (
                  dnaIndicators.map((indicator, index) => (
                    <span className="dna-tag" key={index}>
                      {String(indicator)}
                    </span>
                  ))
                ) : (
                  <p className="empty-state">
                    No Scam DNA indicators returned.
                  </p>
                )}
              </div>

            </div>

            {/* URL INTELLIGENCE */}

            <div className="panel">

              <div className="panel-heading">
                <div>
                  <h3>URL Intelligence</h3>
                  <p>Technical URL analysis returned by backend</p>
                </div>

                <Link size={19} />
              </div>

              {urlAnalysis.length > 0 ? (
                <pre className="json-output">
                  {JSON.stringify(urlAnalysis, null, 2)}
                </pre>
              ) : (
                <p className="empty-state">
                  No URL intelligence data available.
                </p>
              )}

            </div>

          </section>
        )}

        {/* EMPTY STATE */}

        {!result && !loading && (

          <section className="empty-dashboard">

            <div className="empty-icon">
              <Server size={28} />
            </div>

            <h3>Intelligence Engine Ready</h3>

            <p>
              Submit a suspicious message to begin your
              first SHADOWTRACE investigation.
            </p>

          </section>
        )}

        {/* FOOTER */}

        <footer className="footer">

          <span>
            SHADOWTRACE ┬⌐ 2026
          </span>

          <span>
            Rule-Based Scam Intelligence System
          </span>

          <span>
            <RefreshCw size={12} />
            API {apiStatus}
          </span>

        </footer>

      </main>

    </div>
  );
}

export default App;
