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
  source_name: "demo-case.log",
  source_type: "DEMONSTRATION",
  source_reference: "SentinelFlow built-in demonstration",
  report_approval_status: "APPROVED",
  report_approval_feedback: "Demonstration approval only.",
  report_approved_at: "2026-07-29T00:05:00.000Z",
  human_approval_required: true,
  autonomous_remediation_performed: false,
  generated_at: "2026-07-29T00:00:00.000Z",
  prototype_notice:
    "SentinelFlow is a supervised university prototype for simulated cybersecurity logs and is not a replacement for a qualified cybersecurity analyst.",
};

function decodeEncodedReport(encoded) {
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

function encodeReportPayload(report) {
  const bytes = new TextEncoder().encode(JSON.stringify(report));
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return window
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeReportFromHash() {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return decodeEncodedReport(params.get("data"));
}

function enrichApprovedReportUrl(reportUrl, additions) {
  try {
    const url = new URL(reportUrl);
    const params = new URLSearchParams(url.hash.replace(/^#/, ""));
    const report = decodeEncodedReport(params.get("data"));
    if (!report) return reportUrl;

    params.set("data", encodeReportPayload({ ...report, ...additions }));
    url.hash = params.toString();
    return url.toString();
  } catch {
    return reportUrl;
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

const MAX_INPUT_BYTES = 2_000_000;
const MAX_INPUT_CHARACTERS = 40_000;
const MAX_INPUT_EVENTS = 500;
const DEMO_LOG_URL =
  "https://kaandoganknd.github.io/sentinelflow-report/test-data/benign-login.log";
const FLOWISE_API_HOST = "https://cloud.flowiseai.com";
const FLOWISE_FLOW_ID = "6b982cfc-bf9f-4078-8432-cfc0bac3634d";
const ANALYSIS_QUESTION = "Analyse the attached cybersecurity log file.";
const SUPPORTED_FILES = {
  log: "text/plain",
  txt: "text/plain",
  pdf: "application/pdf",
  csv: "text/csv",
  json: "application/json",
};
const REAL_LOG_CASES = [
  {
    id: "SF-REAL-001",
    category: "SIMPLE",
    title: "Linux session open and close",
    source: "Loghub Linux",
    url: "https://kaandoganknd.github.io/sentinelflow-report/test-data/loghub/SF-REAL-001-linux-simple-session.log",
  },
  {
    id: "SF-REAL-002",
    category: "COMPLEX",
    title: "Repeated OpenSSH password failures",
    source: "Loghub OpenSSH",
    url: "https://kaandoganknd.github.io/sentinelflow-report/test-data/loghub/SF-REAL-002-openssh-complex-failures.log",
  },
  {
    id: "SF-REAL-003",
    category: "UNCERTAIN",
    title: "Possible OpenSSH break-in evidence",
    source: "Loghub OpenSSH",
    url: "https://kaandoganknd.github.io/sentinelflow-report/test-data/loghub/SF-REAL-003-openssh-uncertain-breakin.log",
  },
];

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

function getFileExtension(name) {
  return String(name ?? "")
    .split(".")
    .pop()
    .toLowerCase();
}

function safeUploadName(name, extension) {
  const baseName = String(name ?? "SentinelFlow_Log")
    .replace(/\.[^.]+$/, "")
    .replace(/[^A-Za-z0-9_-]/g, "_")
    .slice(0, 80);
  return `${baseName || "SentinelFlow_Log"}.${extension}`;
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () =>
      reject(new Error("The selected file could not be prepared for analysis."));
    reader.readAsDataURL(file);
  });
}

function flowiseResponseText(result) {
  if (typeof result === "string" && result.trim()) return result.trim();
  if (typeof result?.text === "string" && result.text.trim()) {
    return result.text.trim();
  }
  if (typeof result?.json === "string" && result.json.trim()) {
    return result.json.trim();
  }
  if (result?.json && typeof result.json === "object") {
    return JSON.stringify(result.json, null, 2);
  }
  return "SentinelFlow completed the request but did not return a displayable response.";
}

function approvedReportUrl(message) {
  const candidates = String(message ?? "").match(/https:\/\/[^\s)\]]+/g) || [];
  return (
    candidates.find((candidate) => {
      try {
        const url = new URL(candidate);
        return (
          url.hostname === "kaandoganknd.github.io" &&
          url.pathname === "/sentinelflow-report/" &&
          url.hash.startsWith("#data=")
        );
      } catch {
        return false;
      }
    }) || null
  );
}

function cleanFlowiseMessage(message, reportUrl) {
  const original = String(message ?? "");
  if (!reportUrl) return original;

  return original
    .replace(
      /Open the report and select [“"]Download PDF report[”"]:\s*/gi,
      "",
    )
    .replace(/\[[^\]]+\]\(https:\/\/kaandoganknd\.github\.io\/sentinelflow-report\/#data=[^)]+\)/gi, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function hasHumanInputAction(result) {
  const elements = result?.action?.elements;
  return (
    Array.isArray(elements) &&
    elements.some((element) => element?.type === "agentflowv2-approve-button") &&
    elements.some((element) => element?.type === "agentflowv2-reject-button")
  );
}

function parseDraftReport(message) {
  const source = String(message ?? "");
  const fenced = source.match(/```json\s*([\s\S]*?)```/i);
  if (!fenced) return null;

  try {
    const parsed = JSON.parse(fenced[1]);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function InputAdapter() {
  const [mode, setMode] = useState("file");
  const [urlValue, setUrlValue] = useState(DEMO_LOG_URL);
  const [prepared, setPrepared] = useState(null);
  const [status, setStatus] = useState(null);
  const [isFetching, setIsFetching] = useState(false);
  const [phase, setPhase] = useState("idle");
  const [analysisResult, setAnalysisResult] = useState(null);
  const [approvalRequest, setApprovalRequest] = useState(null);
  const [reviewerFeedback, setReviewerFeedback] = useState("");

  function resetResult() {
    setAnalysisResult(null);
    setApprovalRequest(null);
    setReviewerFeedback("");
    setStatus(null);
  }

  function prepareTextContent(
    rawContent,
    sourceName,
    sourceType,
    sourceReference = sourceName,
  ) {
    const checked = validateLogContent(rawContent);
    const uploadName = safeUploadName(sourceName, "txt");
    const uploadFile = new File([checked.content], uploadName, {
      type: "text/plain",
    });
    setPrepared({
      ...checked,
      sourceName,
      sourceType,
      sourceReference,
      uploadFile,
      uploadName,
      converted: getFileExtension(sourceName) === "log" || sourceType === "ALLOWLISTED_URL",
    });
    setPhase("ready");
    setStatus({
      type: "success",
      message: `${checked.eventCount} log line(s) validated. SentinelFlow will receive a secure in-memory TXT version.`,
    });
  }

  async function handleFile(event) {
    const file = event.target.files?.[0];
    setPrepared(null);
    resetResult();
    if (!file) return;

    try {
      setPhase("preparing");
      const extension = getFileExtension(file.name);
      if (!SUPPORTED_FILES[extension]) {
        throw new Error("Select a LOG, TXT, PDF, CSV or JSON file.");
      }
      if (!file.size) {
        throw new Error("The selected file is empty.");
      }
      if (file.size > MAX_INPUT_BYTES) {
        throw new Error(
          `The file exceeds the ${(MAX_INPUT_BYTES / 1_000_000).toFixed(0)} MB prototype limit.`,
        );
      }

      if (extension === "log" || extension === "txt") {
        prepareTextContent(
          await file.text(),
          file.name,
          extension === "log" ? "LOCAL_LOG_FILE" : "LOCAL_TEXT_FILE",
        );
        return;
      }

      const mime = file.type || SUPPORTED_FILES[extension];
      const uploadFile = new File([file], safeUploadName(file.name, extension), {
        type: mime,
      });
      setPrepared({
        sourceName: file.name,
        sourceType: `LOCAL_${extension.toUpperCase()}_FILE`,
        sourceReference: file.name,
        uploadFile,
        uploadName: uploadFile.name,
        converted: false,
        eventCount: null,
        content: null,
      });
      setPhase("ready");
      setStatus({
        type: "success",
        message: `${file.name} is validated and ready for automatic analysis.`,
      });
    } catch (error) {
      setPhase("error");
      setStatus({ type: "error", message: error.message });
    }
  }

  async function handleUrl(event) {
    event.preventDefault();
    setPrepared(null);
    resetResult();
    setIsFetching(true);
    setPhase("preparing");

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

      prepareTextContent(
        await response.text(),
        safeUrl.pathname.split("/").pop() || "remote.log",
        "ALLOWLISTED_URL",
        safeUrl.href,
      );
    } catch (error) {
      const message =
        error.name === "AbortError"
          ? "The allowlisted source did not respond within 8 seconds."
          : error.message;
      setPhase("error");
      setStatus({ type: "error", message });
    } finally {
      window.clearTimeout(timeout);
      setIsFetching(false);
    }
  }

  async function analysePreparedFile() {
    if (!prepared) return;
    setPhase("submitting");
    setAnalysisResult(null);
    setStatus({
      type: "progress",
      message:
        "The file is being analysed. Routing, rule retrieval, ledger validation and Supervisor review may take a moment.",
    });

    try {
      const data = await readFileAsDataUrl(prepared.uploadFile);
      const sessionId =
        typeof crypto.randomUUID === "function"
          ? `sf-web-${crypto.randomUUID()}`
          : `sf-web-${Date.now()}`;
      const response = await fetch(
        `${FLOWISE_API_HOST}/api/v1/prediction/${FLOWISE_FLOW_ID}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "omit",
          body: JSON.stringify({
            question: ANALYSIS_QUESTION,
            streaming: false,
            overrideConfig: { sessionId },
            uploads: [
              {
                type: "file:full",
                name: prepared.uploadName,
                data,
                mime: prepared.uploadFile.type || "text/plain",
              },
            ],
          }),
        },
      );

      if (!response.ok) {
        const detail = await response.text();
        throw new Error(
          response.status === 413
            ? "The prepared request is too large for Flowise."
            : `SentinelFlow returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 180)}` : "."}`,
        );
      }

      const result = await response.json();
      const message = flowiseResponseText(result);

      if (hasHumanInputAction(result)) {
        setApprovalRequest({
          sessionId: result.sessionId || sessionId,
          message,
          draftReport: parseDraftReport(message),
        });
        setPhase("awaiting_approval");
        setStatus({
          type: "approval",
          message:
            "Automated validation and Supervisor review passed. A human reviewer must now approve or reject the draft before PDF delivery.",
        });
        return;
      }

      const reportUrl = approvedReportUrl(message);
      setAnalysisResult({
        message: cleanFlowiseMessage(message, reportUrl),
        reportUrl,
      });
      setPhase("complete");
      setStatus({
        type: "success",
        message: reportUrl
          ? "Analysis passed deterministic validation and Supervisor review. The approved report is ready."
          : "SentinelFlow completed the case. Review the controlled response below.",
      });
    } catch (error) {
      setPhase("error");
      setStatus({
        type: "error",
        message: `The analysis could not be completed: ${error.message}`,
      });
    }
  }

  async function submitHumanDecision(type) {
    if (!approvalRequest) return;

    const feedback = reviewerFeedback.trim();
    if (type === "reject" && !feedback) {
      setStatus({
        type: "error",
        message:
          "Enter a short reason before rejecting the draft report so the decision remains auditable.",
      });
      return;
    }

    setPhase("resuming");
    setStatus({
      type: "progress",
      message:
        type === "proceed"
          ? "Human approval is being recorded and the PDF report is being prepared."
          : "Human rejection and reviewer feedback are being recorded.",
    });

    try {
      const response = await fetch(
        `${FLOWISE_API_HOST}/api/v1/prediction/${FLOWISE_FLOW_ID}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "omit",
          body: JSON.stringify({
            question: "",
            streaming: false,
            overrideConfig: { sessionId: approvalRequest.sessionId },
            humanInput: {
              type,
              feedback:
                feedback ||
                "Approved after human review of the draft report and cited evidence.",
            },
          }),
        },
      );

      if (!response.ok) {
        const detail = await response.text();
        throw new Error(
          `SentinelFlow returned HTTP ${response.status}${detail ? `: ${detail.slice(0, 180)}` : "."}`,
        );
      }

      const result = await response.json();
      const message = flowiseResponseText(result);
      const originalReportUrl = approvedReportUrl(message);
      const reportUrl = originalReportUrl
        ? enrichApprovedReportUrl(originalReportUrl, {
            source_name: prepared?.sourceName || "Not supplied",
            source_type: prepared?.sourceType || "Not supplied",
            source_reference:
              prepared?.sourceReference || prepared?.sourceName || "Not supplied",
            report_approval_status: "APPROVED",
            report_approval_feedback:
              feedback ||
              "Approved after human review of the draft report and cited evidence.",
            report_approved_at: new Date().toISOString(),
          })
        : null;

      setAnalysisResult({
        message: cleanFlowiseMessage(message, originalReportUrl),
        reportUrl,
      });
      setApprovalRequest(null);
      setReviewerFeedback("");
      setPhase("complete");
      setStatus({
        type: reportUrl ? "success" : "approval",
        message: reportUrl
          ? "Human approval was recorded. The approved PDF report is ready."
          : "The draft was rejected by the human reviewer. No approved PDF report was released.",
      });
    } catch (error) {
      setPhase("awaiting_approval");
      setStatus({
        type: "error",
        message: `The human decision could not be recorded: ${error.message}`,
      });
    }
  }

  const phaseIndex = {
    idle: 0,
    preparing: 1,
    ready: 1,
    submitting: 2,
    awaiting_approval: 3,
    resuming: 3,
    complete: 4,
    error: approvalRequest ? 3 : prepared ? 1 : 0,
  }[phase];

  return (
    <main className="page-shell">
      <header className="site-header">
        <div className="brand">
          <span className="brand-mark">SF</span>
          <div>
            <p className="eyebrow">SENTINELFLOW</p>
            <p className="brand-subtitle">Unified cybersecurity log intake</p>
          </div>
        </div>
        <a className="secondary-button" href="./">
          Return to report viewer
        </a>
      </header>

      <section className="privacy-note">
        <strong>Controlled processing:</strong> conversion happens temporarily
        in your browser. The prepared case is sent to the university Flowise
        prototype only when you select <strong>Analyse file</strong>. No file is
        stored by this page. Use simulated or explicitly approved teaching data
        only.
      </section>

      <article className="adapter-card">
        <div className="adapter-heading">
          <p className="eyebrow">ONE UPLOAD · ONE CONTROLLED WORKFLOW</p>
          <h1>Upload once. SentinelFlow handles the rest.</h1>
          <p>
            Submit one LOG, TXT, PDF, CSV or JSON case. Required conversion,
            analysis, evidence checks and report preparation happen in the
            background without a second download or upload.
          </p>
        </div>

        <section className="workflow-steps" aria-label="Analysis workflow">
          {[
            "File selected",
            "Validated and prepared",
            "SentinelFlow analysis",
            "Human approval and result",
          ].map((label, index) => (
            <div
              className={
                index < phaseIndex
                  ? "workflow-step complete"
                  : index === phaseIndex
                    ? "workflow-step active"
                    : "workflow-step"
              }
              key={label}
            >
              <span>{index + 1}</span>
              <p>{label}</p>
            </div>
          ))}
        </section>

        <div className="conversion-heading">
          <p className="eyebrow">CASE SOURCE</p>
          <h2>Select a local file or controlled teaching-data URL</h2>
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
              setPhase("idle");
              resetResult();
            }}
          >
            Local file
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "url"}
            className={mode === "url" ? "active" : ""}
            onClick={() => {
              setMode("url");
              setPrepared(null);
              setPhase("idle");
              resetResult();
            }}
          >
            Allowlisted URL
          </button>
        </div>

        {mode === "file" ? (
          <section className="adapter-panel" role="tabpanel">
            <label className="file-drop">
              <span className="file-drop-title">
                Choose a LOG, TXT, PDF, CSV or JSON file
              </span>
              <span>
                One case per file · Maximum{" "}
                {(MAX_INPUT_BYTES / 1_000_000).toFixed(0)} MB
              </span>
              <input
                type="file"
                accept=".log,.txt,.pdf,.csv,.json,text/plain,text/csv,application/pdf,application/json"
                onChange={handleFile}
              />
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

        <section className="real-test-cases">
          <div>
            <p className="eyebrow">OPENLY ATTRIBUTED ACADEMIC TEST DATA</p>
            <h2>Loghub real-log excerpts</h2>
            <p>
              Small unchanged excerpts selected for simple, complex and
              uncertain-path testing. Source lines, preparation and academic-use
              permission are recorded in the manifest.
            </p>
          </div>
          <div className="real-case-grid">
            {REAL_LOG_CASES.map((testCase) => (
              <article key={testCase.id}>
                <span>{testCase.category}</span>
                <strong>
                  {testCase.id} · {testCase.title}
                </strong>
                <small>{testCase.source}</small>
                <button
                  type="button"
                  onClick={() => {
                    setMode("url");
                    setUrlValue(testCase.url);
                    setPrepared(null);
                    setPhase("idle");
                    resetResult();
                  }}
                >
                  Use this source
                </button>
              </article>
            ))}
          </div>
          <a
            href="./test-data/loghub/source_manifest.json"
            target="_blank"
            rel="noreferrer"
          >
            View source, licence and preparation manifest
          </a>
        </section>

        {status && (
          <section
            className={
              status.type === "success"
                ? "status-success"
                : status.type === "progress"
                  ? "status-progress"
                  : status.type === "approval"
                    ? "status-approval"
                    : "error-note"
            }
            role="status"
            aria-live="polite"
          >
            {status.message}
          </section>
        )}

        {prepared && (
          <section className="prepared-output">
            <div className="prepared-summary">
              <div>
                <p className="eyebrow">READY FOR CONTROLLED ANALYSIS</p>
                <h2>{prepared.sourceName}</h2>
                <p>
                  {prepared.sourceType}
                  {prepared.eventCount !== null &&
                    ` · ${prepared.eventCount} log line(s)`}
                  {prepared.converted && " · converted privately in memory"}
                </p>
              </div>
              <button
                className="download-button"
                type="button"
                onClick={analysePreparedFile}
                disabled={[
                  "submitting",
                  "awaiting_approval",
                  "resuming",
                ].includes(phase)}
              >
                {phase === "submitting"
                  ? "Analysing securely..."
                  : phase === "awaiting_approval"
                    ? "Awaiting human approval"
                    : phase === "resuming"
                      ? "Recording decision..."
                  : "Analyse file"}
              </button>
            </div>
            {prepared.content && (
              <pre>{prepared.content.split("\n").slice(0, 30).join("\n")}</pre>
            )}
            <p className="public-chat-note">
              <strong>University demonstration access:</strong> this public
              prototype uses Flowise without user authentication. Do not submit
              personal, confidential or production security data.
            </p>
          </section>
        )}

        {approvalRequest && (
          <section className="approval-panel">
            <p className="eyebrow">HUMAN APPROVAL CHECKPOINT</p>
            <h2>Review the draft before PDF delivery</h2>
            <p className="approval-intro">
              The deterministic ledger and independent Supervisor have passed.
              The report will not be released until a person checks the
              evidence and records a decision.
            </p>

            {approvalRequest.draftReport ? (
              <>
                <dl className="approval-summary">
                  <div>
                    <dt>Case ID</dt>
                    <dd>{text(approvalRequest.draftReport.case_id)}</dd>
                  </div>
                  <div>
                    <dt>Route</dt>
                    <dd>{text(approvalRequest.draftReport.route)}</dd>
                  </div>
                  <div>
                    <dt>Decision</dt>
                    <dd>{text(approvalRequest.draftReport.decision)}</dd>
                  </div>
                  <div>
                    <dt>Severity</dt>
                    <dd>{text(approvalRequest.draftReport.overall_severity)}</dd>
                  </div>
                </dl>
                <div className="draft-review">
                  <h3>Executive summary</h3>
                  <p>
                    {text(approvalRequest.draftReport.executive_summary)}
                  </p>
                  <h3>Draft findings</h3>
                  {(Array.isArray(approvalRequest.draftReport.findings)
                    ? approvalRequest.draftReport.findings
                    : []
                  ).map((finding, index) => (
                    <article className="draft-finding" key={`${finding.title}-${index}`}>
                      <strong>
                        {index + 1}. {text(finding.title)}
                      </strong>
                      <span>
                        {text(finding.category)} · {text(finding.severity)} ·{" "}
                        {text(finding.event_ids)} · {text(finding.rule_refs)}
                      </span>
                      <p>{text(finding.evidence)}</p>
                    </article>
                  ))}
                </div>
              </>
            ) : (
              <div className="result-message">{approvalRequest.message}</div>
            )}

            <label className="reviewer-feedback">
              Reviewer feedback
              <textarea
                value={reviewerFeedback}
                onChange={(event) => setReviewerFeedback(event.target.value)}
                placeholder="Optional for approval. Required when rejecting the report."
                rows="4"
                disabled={phase === "resuming"}
              />
            </label>

            <div className="approval-actions">
              <button
                className="download-button"
                type="button"
                onClick={() => submitHumanDecision("proceed")}
                disabled={phase === "resuming"}
              >
                {phase === "resuming"
                  ? "Recording decision..."
                  : "Approve and generate PDF"}
              </button>
              <button
                className="reject-button"
                type="button"
                onClick={() => submitHumanDecision("reject")}
                disabled={phase === "resuming"}
              >
                Reject report
              </button>
            </div>
          </section>
        )}

        {analysisResult && (
          <section className="analysis-result">
            <p className="eyebrow">
              {analysisResult.reportUrl
                ? "APPROVED REPORT READY"
                : "CONTROLLED SENTINELFLOW RESPONSE"}
            </p>
            <h2>
              {analysisResult.reportUrl
                ? "The case passed the automated control gates"
                : "The case requires review"}
            </h2>
            <div className="result-message">{analysisResult.message}</div>
            {analysisResult.reportUrl && (
              <a
                className="download-button result-link"
                href={analysisResult.reportUrl}
                target="_blank"
                rel="noreferrer"
              >
                Open approved report and download PDF
              </a>
            )}
          </section>
        )}

        <footer className="adapter-footer">
          This supervised university prototype accepts simulated or approved
          teaching data only. Human approval remains required and no autonomous
          remediation is performed.
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
      addWrapped(
        `Source file: ${text(report.source_name)} | Input type: ${text(
          report.source_type,
        )} | Source reference: ${text(report.source_reference)}`,
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
      addWrapped(
        `Report approval: ${text(
          report.report_approval_status,
          "Not recorded",
        )} | Approved at: ${text(report.report_approved_at, "Not recorded")}`,
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
        `Report release decision: ${text(
          report.report_approval_status,
          "Not recorded",
        )}`,
      );
      addWrapped(`Reviewer feedback: ${text(
        report.report_approval_feedback,
        "Not recorded",
      )}`);
      addWrapped(`Recorded at: ${text(
        report.report_approved_at,
        "Not recorded",
      )}`);
      addWrapped(
        "Operational response authorisation:  Approve / Reject / Escalate / More information required",
      );
      addWrapped(
        "Authorising analyst name: _____________________________________",
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
            Analyse a log file
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
          <div>
            <dt>Source file</dt>
            <dd>{text(report.source_name)}</dd>
          </div>
          <div>
            <dt>Input type</dt>
            <dd>{text(report.source_type)}</dd>
          </div>
        </dl>

        <section className="report-section source-record">
          <h2>Source record</h2>
          <dl>
            <div>
              <dt>Uploaded filename</dt>
              <dd>{text(report.source_name)}</dd>
            </div>
            <div>
              <dt>Source reference</dt>
              <dd>{text(report.source_reference)}</dd>
            </div>
          </dl>
        </section>

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
                <dt>Report release</dt>
                <dd>
                  {text(report.report_approval_status, "Not recorded")}
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
            <h2>Human decision record</h2>
            <p>
              Report release:{" "}
              <strong>
                {text(report.report_approval_status, "Not recorded")}
              </strong>
            </p>
            <p>
              Operational action still requires separate authorisation after
              reviewing the cited evidence and rules.
            </p>
          </div>
          <div className="signature-fields">
            <span>
              Reviewer feedback:{" "}
              {text(report.report_approval_feedback, "Not recorded")}
            </span>
            <span>
              Report decision time:{" "}
              {text(report.report_approved_at, "Not recorded")}
            </span>
            <span>Operational authorisation and analyst name</span>
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
