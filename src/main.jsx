import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const SAMPLE_REPORT = {
  report_title: "SentinelFlow Cybersecurity Triage Report",
  case_id: "SF-DEMO-001",
  route: "COMPLEX",
  decision: "ALERT",
  overall_severity: "HIGH",
  confidence: 0.94,
  executive_summary:
    "This preview demonstrates the human-supervised SentinelFlow report format.",
  findings: [
    {
      category: "INCIDENT",
      title: "Demonstration finding",
      severity: "HIGH",
      event_ids: "E001,E002",
      rule_refs: "SF-AUTH-201",
      evidence: "Exact event evidence supplied by the approved analyst result.",
      assessment:
        "The report preserves the evidence, rule references and independent Supervisor decision.",
      recommended_action:
        "Proposed action: A qualified human analyst should review the evidence before any operational response.",
    },
  ],
  recommended_next_steps: [
    "Proposed action: Review the cited evidence and supporting rule.",
    "Proposed action: Record the final human decision.",
  ],
  limitations: ["Demonstration payload only."],
  validation_status: "PASS",
  supervisor_status: "APPROVED",
  human_approval_required: true,
  autonomous_remediation_performed: false,
  generated_at: "2026-07-29T00:00:00.000Z",
  prototype_notice:
    "SentinelFlow is a supervised university prototype for simulated cybersecurity logs and is not a replacement for a qualified cybersecurity analyst.",
};

function decodeReportFromHash() {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const encoded = params.get("data");
  if (!encoded) return null;

  try {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = window.atob(padded);
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function text(value, fallback = "Not supplied") {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return fallback;
}

function percent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "Not supplied";
  return `${Math.round(number <= 1 ? number * 100 : number)}%`;
}

function severityClass(value) {
  return `severity severity-${text(value, "none").toLowerCase()}`;
}

const MAX_INPUT_BYTES = 100_000;
const MAX_INPUT_CHARACTERS = 40_000;
const MAX_INPUT_EVENTS = 500;
const DEMO_LOG_URL =
  "https://kaandoganknd.github.io/sentinelflow-report/test-data/benign-login.log";

function validateAllowlistedUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Enter a complete HTTPS URL.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Only HTTPS URLs are permitted.");
  }
  if (url.username || url.password) {
    throw new Error("URLs containing credentials are not permitted.");
  }
  if (url.port && url.port !== "443") {
    throw new Error("Only the standard HTTPS port is permitted.");
  }

  const allowed =
    (url.hostname === "kaandoganknd.github.io" &&
      url.pathname.startsWith("/sentinelflow-report/test-data/")) ||
    (url.hostname === "raw.githubusercontent.com" &&
      url.pathname.startsWith("/kaandoganknd/sentinelflow-report/"));

  if (!allowed) {
    throw new Error(
      "URL blocked: only the SentinelFlow teaching-data locations are allowlisted.",
    );
  }

  if (!/\.(log|txt)$/i.test(url.pathname)) {
    throw new Error("The allowlisted URL must point to a .log or .txt file.");
  }

  return url;
}

function validateLogContent(value) {
  const normalised = String(value ?? "")
    .replace(/^\uFEFF/, "")
    .replace(/\r\n?/g, "\n");

  if (!normalised.trim()) {
    throw new Error("The selected source contains no readable log text.");
  }
  if (normalised.includes("\u0000")) {
    throw new Error("Binary or null-byte content is not permitted.");
  }
  if (normalised.length > MAX_INPUT_CHARACTERS) {
    throw new Error(
      `The prototype accepts at most ${MAX_INPUT_CHARACTERS.toLocaleString()} characters per case.`,
    );
  }

  const eventCount = normalised
    .split("\n")
    .filter((line) => line.trim().length > 0).length;
  if (eventCount > MAX_INPUT_EVENTS) {
    throw new Error(
      `The prototype accepts at most ${MAX_INPUT_EVENTS} non-empty log lines per case.`,
    );
  }

  return { content: normalised, eventCount };
}

function InputAdapter() {
  const [mode, setMode] = useState("file");
  const [urlValue, setUrlValue] = useState(DEMO_LOG_URL);
  const [prepared, setPrepared] = useState(null);
  const [status, setStatus] = useState(null);
  const [isFetching, setIsFetching] = useState(false);

  function openSentinelFlowChat() {
    const chatbot = document.querySelector("flowise-chatbot");
    const launcher = chatbot?.shadowRoot?.querySelector("button");

    if (launcher) {
      launcher.click();
      return;
    }

    setStatus({
      type: "error",
      message:
        "The embedded chat is still loading. Please use Open SentinelFlow Chat at the lower right.",
    });
  }

  function prepareContent(rawContent, sourceName, sourceType) {
    const checked = validateLogContent(rawContent);
    setPrepared({
      ...checked,
      sourceName,
      sourceType,
    });
    setStatus({
      type: "success",
      message: `${checked.eventCount} log line(s) validated and ready for Flowise.`,
    });
  }

  async function handleFile(event) {
    const file = event.target.files?.[0];
    setPrepared(null);
    setStatus(null);
    if (!file) return;

    try {
      if (!file.name.toLowerCase().endsWith(".log")) {
        throw new Error("Select a file with the .log extension.");
      }
      if (file.size > MAX_INPUT_BYTES) {
        throw new Error(
          `The file exceeds the ${MAX_INPUT_BYTES.toLocaleString()}-byte intake limit.`,
        );
      }
      prepareContent(await file.text(), file.name, "LOCAL_LOG_FILE");
    } catch (error) {
      setStatus({ type: "error", message: error.message });
    }
  }

  async function handleUrl(event) {
    event.preventDefault();
    setPrepared(null);
    setStatus(null);
    setIsFetching(true);

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 8000);

    try {
      const safeUrl = validateAllowlistedUrl(urlValue.trim());
      const response = await fetch(safeUrl, {
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`The allowlisted source returned HTTP ${response.status}.`);
      }

      const contentLength = Number(response.headers.get("content-length"));
      if (Number.isFinite(contentLength) && contentLength > MAX_INPUT_BYTES) {
        throw new Error("The remote file exceeds the intake size limit.");
      }

      const contentType = response.headers.get("content-type") || "";
      if (
        contentType &&
        !/^(text\/plain|text\/x-log|application\/octet-stream)(?:;|$)/i.test(
          contentType,
        )
      ) {
        throw new Error(`Blocked response content type: ${contentType}.`);
      }

      prepareContent(
        await response.text(),
        safeUrl.pathname.split("/").pop() || "remote.log",
        "ALLOWLISTED_URL",
      );
    } catch (error) {
      const message =
        error.name === "AbortError"
          ? "The allowlisted source did not respond within 8 seconds."
          : error.message;
      setStatus({ type: "error", message });
    } finally {
      window.clearTimeout(timeout);
      setIsFetching(false);
    }
  }

  function downloadPreparedFile() {
    if (!prepared) return;
    const safeBaseName = prepared.sourceName
      .replace(/\.[^.]+$/, "")
      .replace(/[^A-Za-z0-9_-]/g, "_");
    const blob = new Blob([prepared.content], {
      type: "text/plain;charset=utf-8",
    });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `${safeBaseName || "SentinelFlow_Log"}_ready.txt`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  }

  return (
    <main className="page-shell">
      <header className="site-header">
        <div className="brand">
          <span className="brand-mark">SF</span>
          <div>
            <p className="eyebrow">SENTINELFLOW</p>
            <p className="brand-subtitle">Safe log input adapter</p>
          </div>
        </div>
        <a className="secondary-button" href="./">
          Return to report viewer
        </a>
      </header>

      <section className="privacy-note">
        <strong>Controlled processing:</strong> selected files remain in your
        browser while they are validated and converted. They are sent to
        Flowise only if you deliberately attach them in the SentinelFlow Chat.
        URL retrieval is restricted to the displayed teaching-data allowlist.
        No credentials or API keys are embedded in this adapter.
      </section>

      <article className="adapter-card">
        <div className="adapter-heading">
          <p className="eyebrow">CONTROLLED INPUT PREPARATION</p>
          <h1>Submit a cybersecurity log to SentinelFlow</h1>
          <p>
            Upload supported files directly, or safely prepare a LOG file or
            allowlisted online source before analysis.
          </p>
        </div>

        <section className="direct-upload-panel">
          <div>
            <p className="eyebrow">DIRECTLY SUPPORTED FILES</p>
            <h2>Already have TXT, PDF, CSV or JSON?</h2>
            <p>
              No conversion is required. Open SentinelFlow Chat and attach the
              file directly using the paperclip button.
            </p>
          </div>
          <button
            className="download-button"
            type="button"
            onClick={openSentinelFlowChat}
          >
            Open SentinelFlow Chat
          </button>
        </section>

        <div className="conversion-heading">
          <p className="eyebrow">LOG AND ONLINE SOURCE CONVERSION</p>
          <h2>Prepare a source that Flowise cannot attach directly</h2>
        </div>

        <div className="mode-tabs" role="tablist" aria-label="Input source">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "file"}
            className={mode === "file" ? "active" : ""}
            onClick={() => {
              setMode("file");
              setPrepared(null);
              setStatus(null);
            }}
          >
            Local .log file
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "url"}
            className={mode === "url" ? "active" : ""}
            onClick={() => {
              setMode("url");
              setPrepared(null);
              setStatus(null);
            }}
          >
            Allowlisted URL
          </button>
        </div>

        {mode === "file" ? (
          <section className="adapter-panel" role="tabpanel">
            <label className="file-drop">
              <span className="file-drop-title">Choose a .log file</span>
              <span>
                Maximum {MAX_INPUT_CHARACTERS.toLocaleString()} characters and{" "}
                {MAX_INPUT_EVENTS} non-empty lines
              </span>
              <input type="file" accept=".log,text/plain" onChange={handleFile} />
            </label>
          </section>
        ) : (
          <section className="adapter-panel" role="tabpanel">
            <form className="url-form" onSubmit={handleUrl}>
              <label htmlFor="log-url">Allowlisted HTTPS log URL</label>
              <div className="url-row">
                <input
                  id="log-url"
                  type="url"
                  value={urlValue}
                  onChange={(event) => setUrlValue(event.target.value)}
                  spellCheck="false"
                  required
                />
                <button
                  className="download-button"
                  type="submit"
                  disabled={isFetching}
                >
                  {isFetching ? "Checking..." : "Validate URL"}
                </button>
              </div>
            </form>
            <div className="allowlist">
              <strong>Allowlist</strong>
              <code>
                kaandoganknd.github.io/sentinelflow-report/test-data/
              </code>
              <code>
                raw.githubusercontent.com/kaandoganknd/sentinelflow-report/
              </code>
            </div>
          </section>
        )}

        {status && (
          <section
            className={status.type === "success" ? "status-success" : "error-note"}
            role="status"
          >
            {status.message}
          </section>
        )}

        {prepared && (
          <section className="prepared-output">
            <div className="prepared-summary">
              <div>
                <p className="eyebrow">VALIDATED SOURCE</p>
                <h2>{prepared.sourceName}</h2>
                <p>
                  {prepared.sourceType} · {prepared.content.length} characters ·{" "}
                  {prepared.eventCount} log line(s)
                </p>
              </div>
              <button
                className="download-button"
                type="button"
                onClick={downloadPreparedFile}
              >
                Download Flowise-ready TXT
              </button>
            </div>
            <pre>{prepared.content.split("\n").slice(0, 30).join("\n")}</pre>
            <ol className="next-instructions">
              <li>Download the validated TXT file.</li>
              <li>
                Select <strong>Open SentinelFlow Chat</strong> at the lower
                right of this page.
              </li>
              <li>Attach the downloaded TXT file to a new chat.</li>
              <li>
                Send: <code>Analyse the attached cybersecurity log file.</code>
              </li>
            </ol>
            <p className="public-chat-note">
              <strong>University demonstration access:</strong> the embedded
              chat currently uses the Flowise prototype without user
              authentication. Use only simulated or explicitly approved
              teaching data.
            </p>
          </section>
        )}

        <footer className="adapter-footer">
          This supervised university prototype accepts simulated or approved
          teaching data only. Conversion does not perform analysis or autonomous
          remediation.
        </footer>
      </article>
    </main>
  );
}

function App() {
  const [report, setReport] = useState(SAMPLE_REPORT);
  const [isDemo, setIsDemo] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  useEffect(() => {
    const load = () => {
      const hasData = window.location.hash.includes("data=");
      const decoded = decodeReportFromHash();
      setReport(decoded || SAMPLE_REPORT);
      setIsDemo(!decoded);
      setLoadError(hasData && !decoded);
    };

    load();
    window.addEventListener("hashchange", load);
    return () => window.removeEventListener("hashchange", load);
  }, []);

  const generatedAt = useMemo(() => {
    const value = report.generated_at;
    if (!value) return "Not supplied";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toISOString();
  }, [report.generated_at]);

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const nextSteps = Array.isArray(report.recommended_next_steps)
    ? report.recommended_next_steps
    : [];
  const limitations = Array.isArray(report.limitations)
    ? report.limitations
    : [];

  async function downloadPdf() {
    setIsDownloading(true);
    try {
      const { jsPDF } = await import("jspdf");
      const pdf = new jsPDF({ unit: "mm", format: "a4" });
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 16;
      const contentWidth = pageWidth - margin * 2;
      let y = 18;

      const ensureSpace = (required) => {
        if (y + required > pageHeight - 18) {
          pdf.addPage();
          y = 18;
        }
      };

      const addWrapped = (value, options = {}) => {
        const size = options.size ?? 9;
        const indent = options.indent ?? 0;
        pdf.setFont("helvetica", options.bold ? "bold" : "normal");
        pdf.setFontSize(size);
        pdf.setTextColor(...(options.color ?? [31, 41, 55]));
        const lines = pdf.splitTextToSize(text(value), contentWidth - indent);
        const lineHeight = size * 0.42;
        ensureSpace(lines.length * lineHeight + 2);
        pdf.text(lines, margin + indent, y);
        y += lines.length * lineHeight + (options.gapAfter ?? 3);
      };

      const addSection = (title) => {
        ensureSpace(14);
        y += 2;
        pdf.setFillColor(232, 244, 244);
        pdf.roundedRect(margin, y - 5, contentWidth, 9, 1.5, 1.5, "F");
        pdf.setFont("helvetica", "bold");
        pdf.setFontSize(10);
        pdf.setTextColor(9, 91, 92);
        pdf.text(title.toUpperCase(), margin + 3, y + 1);
        y += 9;
      };

      pdf.setFillColor(9, 91, 92);
      pdf.rect(0, 0, pageWidth, 9, "F");
      addWrapped(
        report.report_title || "SentinelFlow Cybersecurity Triage Report",
        { size: 18, bold: true, color: [15, 23, 42], gapAfter: 1 },
      );
      addWrapped(`Case ID: ${text(report.case_id)}`, {
        size: 9,
        bold: true,
        color: [9, 91, 92],
        gapAfter: 5,
      });
      addWrapped(
        [
          `Route: ${text(report.route)}`,
          `Decision: ${text(report.decision)}`,
          `Severity: ${text(report.overall_severity)}`,
          `Confidence: ${percent(report.confidence)}`,
          `Generated: ${generatedAt}`,
        ].join("   |   "),
        { size: 8, color: [71, 85, 105], gapAfter: 5 },
      );

      addSection("Executive summary");
      addWrapped(report.executive_summary);
      addSection("Findings and evidence");

      if (!findings.length) addWrapped("No findings were supplied.");
      findings.forEach((finding, index) => {
        addWrapped(
          `${index + 1}. ${text(finding.title, "Untitled finding")} - ${text(
            finding.severity,
            "UNKNOWN",
          )}`,
          { size: 11, bold: true, color: [15, 23, 42], gapAfter: 2 },
        );
        addWrapped(
          `Category: ${text(finding.category)} | Events: ${text(
            finding.event_ids,
          )} | Rules: ${text(finding.rule_refs)}`,
          { size: 8, bold: true, color: [9, 91, 92], gapAfter: 2 },
        );
        addWrapped(`Evidence: ${text(finding.evidence)}`, { size: 8.5 });
        addWrapped(`Assessment: ${text(finding.assessment)}`, { size: 8.5 });
        addWrapped(`Recommended action: ${text(finding.recommended_action)}`, {
          size: 8.5,
          gapAfter: 5,
        });
      });

      addSection("Recommended next steps");
      if (!nextSteps.length) addWrapped("No next steps were supplied.");
      nextSteps.forEach((step, index) =>
        addWrapped(`${index + 1}. ${step}`, { size: 9, indent: 2, gapAfter: 2 }),
      );

      addSection("Validation and supervision");
      addWrapped(
        `Deterministic validation: ${text(
          report.validation_status,
        )} | Independent Supervisor: ${text(report.supervisor_status)}`,
        { bold: true, gapAfter: 2 },
      );
      addWrapped(
        `Human approval required: ${
          report.human_approval_required === false ? "No" : "Yes"
        } | Autonomous remediation performed: ${
          report.autonomous_remediation_performed === true ? "Yes" : "No"
        }`,
        { bold: true },
      );

      if (limitations.length) {
        addSection("Limitations");
        limitations.forEach((item, index) =>
          addWrapped(`${index + 1}. ${item}`, { size: 8.5, gapAfter: 2 }),
        );
      }

      addSection("Human analyst decision");
      addWrapped(
        "Decision:  Approve / Reject / Escalate / More information required",
      );
      addWrapped(
        "Analyst name: _______________________________________________",
      );
      addWrapped(
        "Date and notes: ______________________________________________",
      );
      addWrapped(
        "____________________________________________________________",
        { gapAfter: 5 },
      );
      addWrapped(report.prototype_notice, {
        size: 7.5,
        color: [100, 116, 139],
      });

      const pageCount = pdf.getNumberOfPages();
      for (let page = 1; page <= pageCount; page += 1) {
        pdf.setPage(page);
        pdf.setDrawColor(203, 213, 225);
        pdf.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
        pdf.setFont("helvetica", "normal");
        pdf.setFontSize(7);
        pdf.setTextColor(100, 116, 139);
        pdf.text(
          `SentinelFlow | ${text(report.case_id)} | Page ${page} of ${pageCount}`,
          margin,
          pageHeight - 7,
        );
      }

      const safeCaseId = text(
        report.case_id,
        "SentinelFlow-Report",
      ).replace(/[^A-Za-z0-9_-]/g, "_");
      pdf.save(`${safeCaseId}_Cybersecurity_Triage_Report.pdf`);
    } finally {
      setIsDownloading(false);
    }
  }

  return (
    <main className="page-shell">
      <header className="site-header">
        <div className="brand">
          <span className="brand-mark">SF</span>
          <div>
            <p className="eyebrow">SENTINELFLOW</p>
            <p className="brand-subtitle">
              Human-supervised cybersecurity triage
            </p>
          </div>
        </div>
        <div className="header-actions">
          <a className="secondary-button" href="?mode=intake">
            Safe Input Adapter
          </a>
          <button
            className="download-button"
            type="button"
            onClick={downloadPdf}
            disabled={isDownloading}
          >
            {isDownloading ? "Preparing PDF..." : "Download PDF report"}
          </button>
        </div>
      </header>

      <section className="privacy-note">
        <strong>Privacy:</strong> report data is processed locally from the URL
        fragment and is not stored by this page. Use simulated or approved
        teaching data only; copied links may remain in browser history.
      </section>

      {loadError && (
        <section className="error-note">
          The report link could not be decoded. A demonstration report is shown.
        </section>
      )}
      {isDemo && !loadError && (
        <section className="demo-note">
          Demonstration mode - open a report link produced by the approved
          SentinelFlow Agentflow to view a live case.
        </section>
      )}

      <article className="report-card">
        <div className="report-heading">
          <div>
            <p className="eyebrow">APPROVED REPORT OUTPUT</p>
            <h1>
              {text(
                report.report_title,
                "SentinelFlow Cybersecurity Triage Report",
              )}
            </h1>
            <p className="case-id">Case ID: {text(report.case_id)}</p>
          </div>
          <span className={severityClass(report.overall_severity)}>
            {text(report.overall_severity, "UNKNOWN")}
          </span>
        </div>

        <dl className="summary-grid">
          <div>
            <dt>Route</dt>
            <dd>{text(report.route)}</dd>
          </div>
          <div>
            <dt>Decision</dt>
            <dd>{text(report.decision)}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{percent(report.confidence)}</dd>
          </div>
          <div>
            <dt>Generated</dt>
            <dd>{generatedAt}</dd>
          </div>
        </dl>

        <section className="report-section">
          <h2>Executive summary</h2>
          <p>{text(report.executive_summary)}</p>
        </section>

        <section className="report-section">
          <div className="section-heading">
            <h2>Findings and evidence</h2>
            <span>{findings.length} finding(s)</span>
          </div>
          <div className="finding-list">
            {!findings.length && <p>No findings were supplied.</p>}
            {findings.map((finding, index) => (
              <article className="finding-card" key={`${finding.title}-${index}`}>
                <div className="finding-heading">
                  <div>
                    <p className="finding-index">FINDING {index + 1}</p>
                    <h3>{text(finding.title, "Untitled finding")}</h3>
                  </div>
                  <span className={severityClass(finding.severity)}>
                    {text(finding.severity, "UNKNOWN")}
                  </span>
                </div>
                <div className="evidence-tags">
                  <span>Category: {text(finding.category)}</span>
                  <span>Events: {text(finding.event_ids)}</span>
                  <span>Rules: {text(finding.rule_refs)}</span>
                </div>
                <dl className="finding-details">
                  <div>
                    <dt>Exact evidence</dt>
                    <dd>{text(finding.evidence)}</dd>
                  </div>
                  <div>
                    <dt>Assessment</dt>
                    <dd>{text(finding.assessment)}</dd>
                  </div>
                  <div>
                    <dt>Human-approved response</dt>
                    <dd>{text(finding.recommended_action)}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        </section>

        <div className="two-column">
          <section className="report-section compact">
            <h2>Recommended next steps</h2>
            {nextSteps.length ? (
              <ol>
                {nextSteps.map((step, index) => (
                  <li key={`${step}-${index}`}>{step}</li>
                ))}
              </ol>
            ) : (
              <p>No next steps were supplied.</p>
            )}
          </section>
          <section className="report-section compact">
            <h2>Independent controls</h2>
            <dl className="control-list">
              <div>
                <dt>Ledger validation</dt>
                <dd>{text(report.validation_status)}</dd>
              </div>
              <div>
                <dt>Supervisor</dt>
                <dd>{text(report.supervisor_status)}</dd>
              </div>
              <div>
                <dt>Human approval</dt>
                <dd>
                  {report.human_approval_required === false
                    ? "Not required"
                    : "Required"}
                </dd>
              </div>
              <div>
                <dt>Autonomous remediation</dt>
                <dd>
                  {report.autonomous_remediation_performed === true
                    ? "Performed"
                    : "Not performed"}
                </dd>
              </div>
            </dl>
          </section>
        </div>

        {!!limitations.length && (
          <section className="report-section">
            <h2>Limitations</h2>
            <ul>
              {limitations.map((item, index) => (
                <li key={`${item}-${index}`}>{item}</li>
              ))}
            </ul>
          </section>
        )}

        <section className="human-decision">
          <div>
            <p className="eyebrow">HUMAN AUTHORITY RETAINED</p>
            <h2>Analyst decision</h2>
            <p>
              Approve, reject, escalate or request more information after
              reviewing the cited evidence and rules.
            </p>
          </div>
          <div className="signature-fields">
            <span>Decision</span>
            <span>Analyst name</span>
            <span>Date and notes</span>
          </div>
        </section>

        <footer className="report-footer">
          <p>{text(report.prototype_notice)}</p>
          <p>
            Autonomous remediation performed:{" "}
            <strong>
              {report.autonomous_remediation_performed === true ? "Yes" : "No"}
            </strong>
          </p>
        </footer>
      </article>
    </main>
  );
}

function RootApp() {
  const mode = new URLSearchParams(window.location.search).get("mode");
  return mode === "intake" ? <InputAdapter /> : <App />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <RootApp />
  </React.StrictMode>,
);
