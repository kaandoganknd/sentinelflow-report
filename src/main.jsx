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

function exactEvidenceText(value, fallback = "Not supplied") {
  if (typeof value === "string" && value.length) return value;
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

function BrandLink({ subtitle }) {
  return (
    <a
      className="brand brand-link"
      href="?mode=intake"
      aria-label="SentinelFlow log intake"
    >
      <img
        className="brand-mark"
        src="./sentinelflow-mark.svg"
        alt=""
        aria-hidden="true"
      />
      <div>
        <p className="eyebrow">SENTINELFLOW</p>
        <p className="brand-subtitle">{subtitle}</p>
      </div>
    </a>
  );
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
    layer: "Simple analyst path",
    title: "Linux session open and close",
    source: "Loghub Linux",
    documentedResult: "HUMAN_REVIEW",
    url: "https://kaandoganknd.github.io/sentinelflow-report/test-data/loghub/SF-REAL-001-linux-simple-session.log",
  },
  {
    id: "SF-REAL-002",
    layer: "Complex correlation",
    title: "Repeated OpenSSH password failures",
    source: "Loghub OpenSSH",
    documentedResult: "HUMAN_REVIEW",
    url: "https://kaandoganknd.github.io/sentinelflow-report/test-data/loghub/SF-REAL-002-openssh-complex-failures.log",
  },
  {
    id: "SF-REAL-003",
    layer: "Routing boundary",
    title: "Possible OpenSSH break-in evidence",
    source: "Loghub OpenSSH",
    documentedResult: "HUMAN_REVIEW before specialist analysis",
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

function buildPhysicalLinePreview(value) {
  const physicalLines = String(value ?? "").split(/\r\n|\n|\r/);
  return {
    previewContent: physicalLines.slice(0, 30).join("\n"),
    nonEmptyPhysicalLineCount: physicalLines.filter(
      (line) => line.trim().length > 0,
    ).length,
  };
}

function formatFileSize(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "Size not supplied";
  return `${bytes.toLocaleString()} bytes`;
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
    .replace(
      /\[[^\]]+\]\(https:\/\/kaandoganknd\.github\.io\/sentinelflow-report\/#data=[^)]+\)/gi,
      "",
    )
    .split(reportUrl)
    .join("")
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
  const candidates = [];

  for (const fenced of source.matchAll(/```json\s*([\s\S]*?)```/gi)) {
    try {
      let candidateText = fenced[1].trim();
      if (
        candidateText.length >= 2 &&
        candidateText.startsWith("`") &&
        candidateText.endsWith("`") &&
        !candidateText.startsWith("```")
      ) {
        candidateText = candidateText.slice(1, -1).trim();
      }

      let parsed = JSON.parse(candidateText);
      if (typeof parsed === "string") {
        let nestedText = parsed.trim();
        if (
          nestedText.length >= 2 &&
          nestedText.startsWith("`") &&
          nestedText.endsWith("`") &&
          !nestedText.startsWith("```")
        ) {
          nestedText = nestedText.slice(1, -1).trim();
        }
        parsed = JSON.parse(nestedText);
      }
      if (parsed && typeof parsed === "object") {
        candidates.push(parsed);
      }
    } catch {
      // Ignore malformed or non-report JSON blocks and continue scanning.
    }
  }

  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const candidate = candidates[index];
    const hasRequiredIdentity = [
      "case_id",
      "route",
      "decision",
      "overall_severity",
    ].every(
      (field) =>
        typeof candidate[field] === "string" && candidate[field].trim(),
    );

    if (hasRequiredIdentity && Array.isArray(candidate.findings)) {
      return candidate;
    }
  }

  return null;
}

function draftEvidenceLines(value) {
  return exactEvidenceText(value).split(/\r?\n| \| /);
}

function draftControlFacts(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const eventIds = findings.flatMap((finding) => {
    if (Array.isArray(finding?.event_ids)) {
      return finding.event_ids.map((eventId) => String(eventId).trim());
    }
    return String(finding?.event_ids ?? "")
      .split(",")
      .map((eventId) => eventId.trim())
      .filter(Boolean);
  });
  const uniqueEventIds = new Set(eventIds);
  const duplicateEventIds = [
    ...new Set(
      eventIds.filter(
        (eventId, index) => eventIds.indexOf(eventId) !== index,
      ),
    ),
  ];

  return [
    {
      label: "Report assembly",
      value: text(report?.report_assembly_status),
    },
    {
      label: "Ledger validation",
      value: text(report?.validation_status),
    },
    {
      label: "Supervisor",
      value: text(report?.supervisor_status),
    },
    {
      label: "Draft event IDs",
      value: `${eventIds.length} listed · ${uniqueEventIds.size} unique`,
    },
    {
      label: "Duplicate event IDs",
      value: duplicateEventIds.length
        ? duplicateEventIds.join(",")
        : "NONE",
    },
    {
      label: "Autonomous remediation",
      value:
        report?.autonomous_remediation_performed === false
          ? "NOT PERFORMED"
          : report?.autonomous_remediation_performed === true
            ? "PERFORMED"
            : "Not supplied",
    },
  ];
}

function StatusNotice({ status, className = "" }) {
  if (!status) return null;

  const statusClass =
    status.type === "success"
      ? "status-success"
      : status.type === "progress"
        ? "status-progress"
        : status.type === "approval"
          ? "status-approval"
          : "error-note";

  return (
    <section
      className={`status-notice ${statusClass} ${className}`.trim()}
      role={status.type === "error" ? "alert" : "status"}
      aria-live="polite"
    >
      {status.message}
    </section>
  );
}

function inferReachedControls(message) {
  const source = String(message ?? "");
  const routingDecision = source.match(
    /\bRouting decision:\s*(SIMPLE|COMPLEX|HUMAN_REVIEW)\b/i,
  )?.[1];
  const supervisorStatus = source.match(
    /\bSupervisor status:\s*(APPROVED|REVISE|HUMAN_REVIEW)\b/i,
  )?.[1];
  const routingHumanReview =
    /SENTINELFLOW\s*[—–-]\s*ROUTING REQUIRES HUMAN REVIEW/i.test(source) ||
    routingDecision?.toUpperCase() === "HUMAN_REVIEW";
  const supervisorReviewReached = Boolean(
    supervisorStatus ||
      /independent Supervisor did not approve/i.test(source) ||
      /automated revision limit was reached before the analysis could pass Supervisor review/i.test(
        source,
      ),
  );

  return {
    orchestratorReached: Boolean(
      routingDecision || routingHumanReview || supervisorReviewReached,
    ),
    specialistReached: supervisorReviewReached,
    ledgerReached: supervisorReviewReached,
    supervisorReviewReached,
  };
}

function ControlJourney({
  phase,
  prepared,
  approvalRequest,
  controlRecord,
  releaseOutcome,
  responseMessage,
}) {
  const isProcessing = phase === "submitting";
  const inferredControls = inferReachedControls(responseMessage);
  const automatedControlsConfirmed = Boolean(
    approvalRequest ||
      (controlRecord &&
        controlRecord.validation_status === "PASS" &&
        controlRecord.supervisor_status === "APPROVED"),
  );
  const controlledResponse = releaseOutcome === "controlled_response";
  const humanDecisionRecorded = [
    "released",
    "integrity_blocked",
    "no_link",
    "rejected",
  ].includes(releaseOutcome);

  const processingState = prepared ? "ready" : "pending";
  const reachedState = (reached) =>
    reached
      ? "confirmed"
      : controlledResponse
        ? "not-reached"
        : processingState;

  const stages = [
    {
      label: "Orchestrator",
      detail: "Selects SIMPLE, COMPLEX or HUMAN_REVIEW",
      state: reachedState(
        automatedControlsConfirmed ||
          controlledResponse ||
          inferredControls.orchestratorReached,
      ),
    },
    {
      label: "Specialist analysis",
      detail: "Applies the route-specific evidence contract",
      state: reachedState(
        automatedControlsConfirmed || inferredControls.specialistReached,
      ),
    },
    {
      label: "Ledger validation",
      detail: "Checks event assignment, rules and severity",
      state: reachedState(
        controlRecord?.validation_status === "PASS" ||
          inferredControls.ledgerReached,
      ),
    },
    {
      label: "Supervisor + guard",
      detail:
        "Supervisor reviews; the deterministic guard enforces the contract.",
      state: reachedState(
        controlRecord?.supervisor_status === "APPROVED" ||
          inferredControls.supervisorReviewReached,
      ),
    },
    {
      label: "Human approval",
      detail: "Retains authority before report delivery",
      state: approvalRequest
        ? "current"
        : releaseOutcome === "rejected"
          ? "stopped"
          : humanDecisionRecorded
            ? "confirmed"
            : controlledResponse
              ? "not-reached"
              : "pending",
    },
    {
      label: "Evidence release gate",
      detail: "Rechecks canonical evidence before publication",
      state:
        releaseOutcome === "released"
          ? "confirmed"
          : releaseOutcome === "integrity_blocked" ||
              releaseOutcome === "no_link"
            ? "blocked"
            : releaseOutcome === "rejected"
              ? "stopped"
              : controlledResponse
                ? "not-reached"
                : "pending",
    },
  ];

  const stateLabels = {
    pending: "Pending",
    ready: "Ready",
    confirmed: "Confirmed",
    current: "Current",
    blocked: "Blocked",
    stopped: "Stopped",
    "not-reached": "Not reached",
  };

  const releaseValue = {
    released: "RELEASED",
    integrity_blocked: "BLOCKED",
    no_link: "NO LINK RETURNED",
    rejected: "REJECTED",
    controlled_response: "NOT REACHED",
  }[releaseOutcome];

  const confirmedFacts = [
    {
      label: "Ledger validation",
      value: controlRecord?.validation_status,
    },
    {
      label: "Supervisor",
      value: controlRecord?.supervisor_status,
    },
    {
      label: "Human approval",
      value:
        controlRecord?.human_approval_required === true
          ? "REQUIRED"
          : controlRecord?.human_approval_required === false
            ? "NOT REQUIRED"
            : undefined,
    },
    {
      label: "Autonomous remediation",
      value:
        controlRecord?.autonomous_remediation_performed === true
          ? "PERFORMED"
          : controlRecord?.autonomous_remediation_performed === false
            ? "NOT PERFORMED"
            : undefined,
    },
    {
      label: "Report release",
      value: releaseValue,
    },
  ].filter((fact) => fact.value);

  return (
    <section className="control-journey" aria-labelledby="control-journey-title">
      <div className="control-journey-heading">
        <div>
          <p className="eyebrow">CONTROL JOURNEY</p>
          <h2 id="control-journey-title">How this case is governed</h2>
        </div>
        <p>
          Flowise returns one response, not a live trace. Processing layers are
          therefore shown together and marked confirmed only when the response
          provides evidence.
        </p>
      </div>

      {isProcessing ? (
        <p className="control-journey-waiting" role="status">
          Analysis in progress. Stage results are reported when the response
          arrives.
        </p>
      ) : (
        <ol className="control-layer-list">
          {stages.map((stage, index) => (
            <li className={`control-layer ${stage.state}`} key={stage.label}>
              <span className="control-layer-index">{index + 1}</span>
              <div>
                <strong>{stage.label}</strong>
                <small>{stage.detail}</small>
              </div>
              <span className="control-layer-state">
                {stateLabels[stage.state]}
              </span>
            </li>
          ))}
        </ol>
      )}

      {!isProcessing && !!confirmedFacts.length && (
        <dl className="confirmed-control-facts">
          {confirmedFacts.map((fact) => (
            <div key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
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
  const [controlRecord, setControlRecord] = useState(null);
  const [releaseOutcome, setReleaseOutcome] = useState(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const intakeLocked = [
    "submitting",
    "awaiting_approval",
    "resuming",
  ].includes(phase);

  function resetResult() {
    setAnalysisResult(null);
    setApprovalRequest(null);
    setReviewerFeedback("");
    setControlRecord(null);
    setReleaseOutcome(null);
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

  async function prepareSelectedFile(file) {
    if (intakeLocked) return;
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
      const preview = ["csv", "json"].includes(extension)
        ? buildPhysicalLinePreview(await file.text())
        : null;
      setPrepared({
        sourceName: file.name,
        sourceType: `LOCAL_${extension.toUpperCase()}_FILE`,
        sourceReference: file.name,
        sourceSizeBytes: file.size,
        uploadFile,
        uploadName: uploadFile.name,
        converted: false,
        eventCount: null,
        content: null,
        previewContent: preview?.previewContent ?? null,
        nonEmptyPhysicalLineCount:
          preview?.nonEmptyPhysicalLineCount ?? null,
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

  async function handleFile(event) {
    const files = event.target.files;
    const file = files?.[0];
    event.target.value = "";

    if (files?.length > 1) {
      setPrepared(null);
      resetResult();
      setPhase("error");
      setStatus({
        type: "error",
        message: "Select one case file at a time.",
      });
      return;
    }

    await prepareSelectedFile(file);
  }

  async function handleFileDrop(event) {
    event.preventDefault();
    setIsDraggingFile(false);
    if (intakeLocked) return;
    const files = event.dataTransfer.files;

    if (files.length !== 1) {
      setPrepared(null);
      resetResult();
      setPhase("error");
      setStatus({
        type: "error",
        message: "Drop one LOG, TXT, PDF, CSV or JSON case file.",
      });
      return;
    }

    await prepareSelectedFile(files[0]);
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
    setControlRecord(null);
    setReleaseOutcome(null);
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
      const draftReport = parseDraftReport(message);

      if (hasHumanInputAction(result)) {
        setApprovalRequest({
          sessionId: result.sessionId || sessionId,
          message,
          draftReport,
        });
        setControlRecord(draftReport);
        setPhase("awaiting_approval");
        setStatus({
          type: draftReport ? "approval" : "error",
          message: draftReport
            ? "Automated validation and Supervisor review passed. A human reviewer must now approve or reject the draft before PDF delivery."
            : "Human approval is unavailable because the response did not contain the complete deterministic report payload. The draft can be rejected, but it cannot be approved or released from this page.",
        });
        return;
      }

      const reportUrl = approvedReportUrl(message);
      setAnalysisResult({
        message: cleanFlowiseMessage(message, reportUrl),
        reportUrl,
      });
      setControlRecord(draftReport);
      setReleaseOutcome(reportUrl ? "released" : "controlled_response");
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

      const approvalStatusByDecision = Object.freeze({
        proceed: "APPROVED",
        reject: "REJECTED",
      });

      const reportApprovalStatus = approvalStatusByDecision[type];

      if (!reportApprovalStatus) {
        throw new Error("Unsupported human decision type");
      }

      const reportUrl =
        type === "proceed" && originalReportUrl
          ? enrichApprovedReportUrl(originalReportUrl, {
              source_name: prepared?.sourceName || "Not supplied",
              source_type: prepared?.sourceType || "Not supplied",
              source_reference:
                prepared?.sourceReference ||
                prepared?.sourceName ||
                "Not supplied",
              report_approval_status: reportApprovalStatus,
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

      const integrityBlocked =
        type === "proceed" &&
        /REPORT_LINK_NOT_CREATED/i.test(message);

      let statusType;
      let statusMessage;

      if (type === "reject") {
        setReleaseOutcome("rejected");
        statusType = "approval";
        statusMessage =
          "The draft was rejected by the human reviewer. No approved PDF report was released.";
      } else if (integrityBlocked) {
        setReleaseOutcome("integrity_blocked");
        statusType = "error";
        statusMessage =
          "Human approval was recorded, but the deterministic release gate blocked publication because the report evidence did not exactly match the supplied records. No PDF was released.";
      } else if (reportUrl) {
        setReleaseOutcome("released");
        statusType = "success";
        statusMessage =
          "Human approval was recorded. The approved PDF report is ready.";
      } else {
        setReleaseOutcome("no_link");
        statusType = "approval";
        statusMessage =
          "Human approval was recorded, but no approved report link was returned. Review the controlled response below.";
      }

      setStatus({ type: statusType, message: statusMessage });
    } catch (error) {
      setPhase("awaiting_approval");
      setStatus({
        type: "error",
        message: `The human decision could not be recorded: ${error.message}`,
      });
    }
  }

  return (
    <main className="page-shell">
      <header className="site-header">
        <BrandLink subtitle="Unified cybersecurity log intake" />
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
          <h1>Structured evidence. Human-controlled decisions.</h1>
          <p>
            Submit one LOG, TXT, PDF, CSV or JSON case. Required conversion,
            analysis, evidence checks and report preparation happen in the
            background without a second download or upload.
          </p>
        </div>

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
            <label
              className={`file-drop${isDraggingFile ? " is-dragging" : ""}${
                intakeLocked ? " is-locked" : ""
              }`}
              onDragEnter={(event) => {
                event.preventDefault();
                if (intakeLocked) return;
                setIsDraggingFile(true);
              }}
              onDragOver={(event) => {
                event.preventDefault();
                if (intakeLocked) return;
                event.dataTransfer.dropEffect = "copy";
                setIsDraggingFile(true);
              }}
              onDragLeave={(event) => {
                const nextTarget = event.relatedTarget;
                if (
                  !(nextTarget instanceof Node) ||
                  !event.currentTarget.contains(nextTarget)
                ) {
                  setIsDraggingFile(false);
                }
              }}
              onDrop={handleFileDrop}
            >
              <span className="file-drop-title">
                Choose or drop a LOG, TXT, PDF, CSV or JSON file
              </span>
              <span>
                One case per file · Maximum{" "}
                {(MAX_INPUT_BYTES / 1_000_000).toFixed(0)} MB
              </span>
              <input
                type="file"
                accept=".log,.txt,.pdf,.csv,.json,text/plain,text/csv,application/pdf,application/json"
                onChange={handleFile}
                disabled={intakeLocked}
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

        {!prepared && <StatusNotice status={status} className="source-status" />}

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
                  ? "Controlled analysis in progress..."
                  : phase === "awaiting_approval"
                    ? "Awaiting human approval"
                    : phase === "resuming"
                      ? "Recording decision..."
                  : "Analyse file"}
              </button>
            </div>
            {!approvalRequest && !analysisResult && (
              <StatusNotice status={status} />
            )}
            {prepared.content && (
              <pre>{prepared.content.split("\n").slice(0, 30).join("\n")}</pre>
            )}
            {prepared.previewContent !== null &&
              prepared.previewContent !== undefined && (
                <section className="source-preview">
                  <div className="source-preview-heading">
                    <h3>Source preview — first 30 physical lines</h3>
                    <span>
                      {prepared.nonEmptyPhysicalLineCount} non-empty physical
                      lines
                    </span>
                  </div>
                  <pre>{prepared.previewContent}</pre>
                  <p className="source-preview-note">
                    Preview only; the original file is submitted unchanged.
                    Event count is confirmed after normalisation.
                  </p>
                </section>
              )}
            {prepared.sourceType === "LOCAL_PDF_FILE" && (
              <section className="pdf-preview-note">
                <div>
                  <strong>{prepared.sourceName}</strong>
                  <span>{formatFileSize(prepared.sourceSizeBytes)}</span>
                </div>
                <p>
                  PDF source preview is not available. The original file will
                  be submitted unchanged.
                </p>
              </section>
            )}
            <p className="public-chat-note">
              <strong>University demonstration access:</strong> this public
              prototype uses Flowise without user authentication. Do not submit
              personal, confidential or production security data.
            </p>
          </section>
        )}

        {["submitting", "resuming"].includes(phase) && (
          <div className="analysis-activity" role="status" aria-live="polite">
            <span className="activity-spinner" aria-hidden="true" />
            <div>
              <strong>
                {phase === "resuming"
                  ? "Recording the human decision"
                  : "Controlled analysis request in progress"}
              </strong>
              <span>
                Please keep this tab in the foreground until analysis
                completes. Switching away can interrupt the connection.
              </span>
            </div>
          </div>
        )}

        <ControlJourney
          phase={phase}
          prepared={prepared}
          approvalRequest={approvalRequest}
          controlRecord={controlRecord}
          releaseOutcome={releaseOutcome}
          responseMessage={
            approvalRequest?.message || analysisResult?.message || ""
          }
        />

        {approvalRequest && (
          <section className="approval-panel">
            <p className="eyebrow">HUMAN APPROVAL CHECKPOINT</p>
            <h2>Review the draft before PDF delivery</h2>
            <p className="approval-intro">
              The deterministic ledger and independent Supervisor have passed.
              The report will not be released until a person checks the
              evidence and records a decision.
            </p>
            {status?.type !== "error" && <StatusNotice status={status} />}

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
                    <dd>
                      <span
                        className={severityClass(
                          approvalRequest.draftReport.overall_severity,
                        )}
                      >
                        {text(
                          approvalRequest.draftReport.overall_severity,
                          "UNKNOWN",
                        )}
                      </span>
                    </dd>
                  </div>
                </dl>
                <dl className="draft-control-summary">
                  {draftControlFacts(approvalRequest.draftReport).map(
                    (fact) => (
                      <div key={fact.label}>
                        <dt>{fact.label}</dt>
                        <dd>{fact.value}</dd>
                      </div>
                    ),
                  )}
                </dl>
                <section className="approval-source-review">
                  <h3>Source under review</h3>
                  <dl className="approval-source-summary">
                    <div>
                      <dt>Filename</dt>
                      <dd>{text(prepared?.sourceName)}</dd>
                    </div>
                    <div>
                      <dt>Input type</dt>
                      <dd>{text(prepared?.sourceType)}</dd>
                    </div>
                    <div>
                      <dt>Source reference</dt>
                      <dd>{text(prepared?.sourceReference)}</dd>
                    </div>
                    <div>
                      <dt>Input fingerprint (prototype)</dt>
                      <dd>
                        {text(approvalRequest.draftReport.content_hash)}
                      </dd>
                    </div>
                  </dl>
                </section>
                <div className="draft-review">
                  <h3>Report title</h3>
                  <p>{text(approvalRequest.draftReport.report_title)}</p>
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
                      <div className="draft-finding-heading">
                        <strong>
                          {index + 1}. {text(finding.title)}
                        </strong>
                        <span className={severityClass(finding.severity)}>
                          {text(finding.severity, "UNKNOWN")}
                        </span>
                      </div>
                      <span>
                        {text(finding.category)} · {text(finding.event_ids)} ·{" "}
                        {text(finding.rule_refs)}
                      </span>
                      <p className="draft-field-label">Assessment</p>
                      <p>{text(finding.assessment)}</p>
                      <p className="draft-field-label">
                        Recommended action
                      </p>
                      <p>{text(finding.recommended_action)}</p>
                      <p className="draft-field-label">
                        Canonical evidence — one record per line
                      </p>
                      <div className="evidence-record evidence-record-compact evidence-record-list">
                        {draftEvidenceLines(finding.evidence).map(
                          (evidenceLine, evidenceIndex) => (
                            <code
                              key={`${finding.finding_id || index}-${evidenceIndex}`}
                            >
                              {evidenceLine}
                            </code>
                          ),
                        )}
                      </div>
                    </article>
                  ))}
                  {Array.isArray(
                    approvalRequest.draftReport.recommended_next_steps,
                  ) &&
                    approvalRequest.draftReport.recommended_next_steps.length >
                      0 && (
                      <section className="draft-list">
                        <h3>Recommended next steps</h3>
                        <ul>
                          {approvalRequest.draftReport.recommended_next_steps.map(
                            (item, index) => (
                              <li key={`next-step-${index}`}>
                                {text(item)}
                              </li>
                            ),
                          )}
                        </ul>
                      </section>
                    )}
                  {Array.isArray(approvalRequest.draftReport.limitations) &&
                    approvalRequest.draftReport.limitations.length > 0 && (
                      <section className="draft-list">
                        <h3>Limitations</h3>
                        <ul>
                          {approvalRequest.draftReport.limitations.map(
                            (item, index) => (
                              <li key={`limitation-${index}`}>
                                {text(item)}
                              </li>
                            ),
                          )}
                        </ul>
                      </section>
                    )}
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
            {status?.type === "error" && (
              <StatusNotice status={status} className="feedback-status" />
            )}

            <p className="approval-release-boundary">
              Approval releases this report only; it does not authorise
              operational remediation.
            </p>
            <div className="approval-actions">
              <button
                className="download-button"
                type="button"
                onClick={() => submitHumanDecision("proceed")}
                disabled={
                  phase === "resuming" || !approvalRequest.draftReport
                }
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
            <StatusNotice status={status} />
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

        <section className="real-test-cases">
          <div className="real-test-heading">
            <div>
              <p className="eyebrow">ATTRIBUTED ACADEMIC TEST DATA</p>
              <h2>Verified Loghub excerpts</h2>
            </div>
            <a
              href="?mode=manifest"
            >
              Source, licence and preparation manifest
            </a>
          </div>
          <div className="real-case-list">
            {REAL_LOG_CASES.map((testCase) => (
              <article key={testCase.id}>
                <span className="real-case-layer">{testCase.layer}</span>
                <div className="real-case-identity">
                  <strong>
                    {testCase.id} · {testCase.title}
                  </strong>
                  <small>{testCase.source}</small>
                </div>
                <span className="real-case-result">
                  <small>Documented result</small>
                  <strong>{testCase.documentedResult}</strong>
                </span>
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
        </section>

        <footer className="adapter-footer">
          This supervised university prototype accepts simulated or approved
          teaching data only. Human approval remains required and no autonomous
          remediation is performed.
        </footer>
      </article>
    </main>
  );
}

function SourceManifestPage() {
  const [manifest, setManifest] = useState(null);
  const [observations, setObservations] = useState(null);
  const [manifestError, setManifestError] = useState("");

  useEffect(() => {
    let active = true;

    Promise.all([
      fetch("./test-data/loghub/source_manifest.json").then((response) => {
        if (!response.ok) {
          throw new Error(`Prediction manifest returned HTTP ${response.status}`);
        }
        return response.json();
      }),
      fetch("./test-data/loghub/source_observations.json").then((response) => {
        if (!response.ok) {
          throw new Error(`Observation record returned HTTP ${response.status}`);
        }
        return response.json();
      }),
    ])
      .then(([predictionManifest, observationRecord]) => {
        if (!active) return;
        setManifest(predictionManifest);
        setObservations(observationRecord);
      })
      .catch((error) => {
        if (active) setManifestError(error.message);
      });

    return () => {
      active = false;
    };
  }, []);

  const observedCases = Array.isArray(observations?.cases)
    ? observations.cases
    : [];
  const observationByTestId = new Map(
    observedCases.map((item) => [item.test_id, item]),
  );
  const predictedCases = Array.isArray(manifest?.cases) ? manifest.cases : [];

  return (
    <main className="page-shell">
      <header className="site-header">
        <BrandLink subtitle="Attributed academic test evidence" />
        <a className="secondary-button" href="?mode=intake">
          Return to log intake
        </a>
      </header>

      <article className="manifest-card">
        <header className="manifest-heading">
          <p className="eyebrow">SOURCE AND EXECUTION EVIDENCE</p>
          <h1>Loghub test manifest</h1>
          <p>
            Source attribution and pre-specified expectations are shown beside
            one contemporaneous set of observed SentinelFlow executions.
          </p>
        </header>

        {manifestError && (
          <section className="error-note manifest-notice">
            The evidence records could not be loaded: {manifestError}
          </section>
        )}

        {!manifest && !manifestError && (
          <section className="status-progress manifest-notice" role="status">
            Loading the evidence records…
          </section>
        )}

        {manifest && observations && (
          <>
            <section className="manifest-section">
              <div className="manifest-section-heading">
                <div>
                  <p className="eyebrow">ATTRIBUTION AND PERMISSION</p>
                  <h2>Dataset record</h2>
                </div>
                <span>Manifest version {text(manifest.manifest_version)}</span>
              </div>
              <dl className="manifest-facts">
                <div>
                  <dt>Publisher</dt>
                  <dd>{text(manifest.publisher)}</dd>
                </div>
                <div>
                  <dt>Repository</dt>
                  <dd>
                    <a href={manifest.repository} target="_blank" rel="noreferrer">
                      LogPAI / Loghub repository
                    </a>
                  </dd>
                </div>
                <div>
                  <dt>Licence notice</dt>
                  <dd>
                    <a href={manifest.licence_url} target="_blank" rel="noreferrer">
                      View the repository licence
                    </a>
                  </dd>
                </div>
                <div>
                  <dt>Prepared for</dt>
                  <dd>{text(manifest.prepared_for)}</dd>
                </div>
              </dl>
              <div className="manifest-prose">
                <h3>Permission statement</h3>
                <p>{text(manifest.permission)}</p>
                <h3>Citation</h3>
                <p>{text(manifest.citation)}</p>
                <h3>Privacy note</h3>
                <p>{text(manifest.privacy_note)}</p>
              </div>
            </section>

            <section className="manifest-section">
              <p className="eyebrow">PREPARATION METHOD</p>
              <h2>Evidence handling</h2>
              <p className="manifest-body">{text(manifest.preparation)}</p>
              <p className="manifest-caveat">
                The expectations below were committed before execution, but
                were not formally preregistered. The original JSON remains
                available unchanged. Its legacy category{" "}
                <code>UNCERTAIN</code> is presented here using the current
                interface label <strong>Routing boundary</strong>.
              </p>
            </section>

            <section className="manifest-section">
              <div className="manifest-section-heading">
                <div>
                  <p className="eyebrow">PREDICTION VERSUS OBSERVATION</p>
                  <h2>Three attributed test cases</h2>
                </div>
                <span>{text(observations.observation_set)}</span>
              </div>

              <div className="manifest-case-list">
                {predictedCases.map((testCase) => {
                  const observation = observationByTestId.get(testCase.test_id);
                  const currentCase = REAL_LOG_CASES.find(
                    (item) => item.id === testCase.test_id,
                  );
                  const routeMatched =
                    observation?.observed_route === testCase.expected_route;
                  const specialistReached =
                    observation?.specialist_decision !== "NOT_REACHED";
                  const decisionMatched =
                    specialistReached &&
                    observation?.specialist_decision ===
                      testCase.expected_decision;
                  const resultLabel = !observation
                    ? "Observation unavailable"
                    : routeMatched && decisionMatched
                      ? "Prediction matched"
                      : routeMatched && !specialistReached
                        ? "Route matched · specialist decision not reached"
                        : "Prediction differed";

                  return (
                    <article
                      className="manifest-case"
                      key={testCase.test_id}
                    >
                      <div className="manifest-case-title">
                        <div>
                          <p className="eyebrow">
                            {currentCase?.layer ||
                              text(testCase.category, "Test case")}
                          </p>
                          <h3>
                            {testCase.test_id} ·{" "}
                            {currentCase?.title || testCase.file}
                          </h3>
                        </div>
                        <span
                          className={`comparison-status ${
                            routeMatched &&
                            (decisionMatched || !specialistReached)
                              ? "matched"
                              : "different"
                          }`}
                        >
                          {resultLabel}
                        </span>
                      </div>

                      <dl className="prediction-grid">
                        <div>
                          <dt>Expected route</dt>
                          <dd>{text(testCase.expected_route)}</dd>
                        </div>
                        <div>
                          <dt>Observed route</dt>
                          <dd>{text(observation?.observed_route)}</dd>
                        </div>
                        <div>
                          <dt>Expected decision</dt>
                          <dd>{text(testCase.expected_decision)}</dd>
                        </div>
                        <div>
                          <dt>Observed specialist decision</dt>
                          <dd>
                            {specialistReached
                              ? text(observation?.specialist_decision)
                              : "Not reached — routing boundary halted automated analysis"}
                          </dd>
                        </div>
                      </dl>

                      <div className="manifest-case-columns">
                        <section>
                          <h4>Source evidence</h4>
                          <dl className="manifest-detail-list">
                            <div>
                              <dt>Dataset</dt>
                              <dd>{text(testCase.dataset)}</dd>
                            </div>
                            <div>
                              <dt>Source file and lines</dt>
                              <dd>
                                {text(testCase.source_file)} ·{" "}
                                {text(testCase.source_lines)}
                              </dd>
                            </div>
                            <div>
                              <dt>Source</dt>
                              <dd>
                                <a
                                  href={testCase.source_url}
                                  target="_blank"
                                  rel="noreferrer"
                                >
                                  Open the attributed source file
                                </a>
                              </dd>
                            </div>
                            <div>
                              <dt>Expected event count</dt>
                              <dd>{text(testCase.expected_event_count)}</dd>
                            </div>
                          </dl>
                          <p>{text(testCase.expected_reason)}</p>
                        </section>

                        <section>
                          <h4>Observed execution</h4>
                          <dl className="manifest-detail-list">
                            <div>
                              <dt>Executed</dt>
                              <dd>{text(observation?.executed)}</dd>
                            </div>
                            <div>
                              <dt>Case ID</dt>
                              <dd>
                                <code>{text(observation?.case_id)}</code>
                              </dd>
                            </div>
                            <div>
                              <dt>Flowise session</dt>
                              <dd>
                                <code>
                                  {text(observation?.flowise_session_id)}
                                </code>
                              </dd>
                            </div>
                            <div>
                              <dt>Input fingerprint</dt>
                              <dd>
                                <code>{text(observation?.content_hash)}</code>
                              </dd>
                            </div>
                            <div>
                              <dt>Event and character counts</dt>
                              <dd>
                                {text(observation?.event_count)} events ·{" "}
                                {text(observation?.original_character_count)}{" "}
                                original characters ·{" "}
                                {text(observation?.received_character_count)}{" "}
                                received
                              </dd>
                            </div>
                            <div>
                              <dt>Source as received</dt>
                              <dd>
                                {text(observation?.source_name)} ·{" "}
                                {text(observation?.source_type)}
                              </dd>
                            </div>
                            <div>
                              <dt>Parse warnings</dt>
                              <dd>
                                {Array.isArray(observation?.parse_warnings) &&
                                observation.parse_warnings.length
                                  ? observation.parse_warnings.join(" · ")
                                  : "None"}
                              </dd>
                            </div>
                            <div>
                              <dt>Release outcome</dt>
                              <dd>{text(observation?.release_status)}</dd>
                            </div>
                          </dl>
                          <p>{text(observation?.trace_result)}</p>
                        </section>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="manifest-section manifest-technical-note">
              <p className="eyebrow">INTERPRETATION NOTE</p>
              <h2>Fingerprint sensitivity</h2>
              <p>{text(observations.fingerprint_note)}</p>
              <p className="manifest-machine-note">
                The underlying records are provided for independent
                verification. They are machine-readable JSON rather than
                formatted pages; the key attribution, prediction and execution
                values are presented above.
              </p>
              <div className="manifest-downloads">
                <a
                  className="secondary-button"
                  href="./test-data/loghub/source_manifest.json"
                  target="_blank"
                  rel="noreferrer"
                >
                  Original prediction JSON
                </a>
                <a
                  className="secondary-button"
                  href="./test-data/loghub/source_observations.json"
                  target="_blank"
                  rel="noreferrer"
                >
                  Observed execution JSON
                </a>
              </div>
            </section>
          </>
        )}

        <footer className="adapter-footer">
          These excerpts are approved academic test evidence, not live
          operational intelligence. SentinelFlow remains human supervised and
          performs no autonomous remediation.
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
        <BrandLink subtitle="Human-supervised cybersecurity triage" />
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
            <div className="source-record-wide">
              <dt>Input fingerprint (prototype)</dt>
              <dd>{text(report.content_hash)}</dd>
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
                    <dd className="evidence-record evidence-record-list">
                      {draftEvidenceLines(finding.evidence).map(
                        (evidenceLine, evidenceIndex) => (
                          <code
                            key={`${finding.finding_id || index}-${evidenceIndex}`}
                          >
                            {evidenceLine}
                          </code>
                        ),
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Assessment</dt>
                    <dd>{text(finding.assessment)}</dd>
                  </div>
                  <div>
                    <dt>Recommended response in approved report</dt>
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
                <dt>Report assembly</dt>
                <dd>
                  {text(report.report_assembly_status, "Not recorded")}
                </dd>
              </div>
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
            <span>
              Operational authorisation: Not recorded in this report
            </span>
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
  if (mode === "intake") return <InputAdapter />;
  if (mode === "manifest") return <SourceManifestPage />;
  return <App />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <RootApp />
  </React.StrictMode>,
);
