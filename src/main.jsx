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
        <button
          className="download-button"
          type="button"
          onClick={downloadPdf}
          disabled={isDownloading}
        >
          {isDownloading ? "Preparing PDF..." : "Download PDF report"}
        </button>
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

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
