import { useState } from "react";
import { useRealtime } from "../hooks/useRealtime.js";

const MAX_EXECUTIONS = 10;
const STEP_ICON = { completed: "✓", running: "⏳", failed: "✗", awaiting_approval: "⏳", skipped_duplicate: "↷" };
const STATUS_PILL = {
  running: "pill-status-open", awaiting_approval: "pill-status-investigating",
  completed: "pill-status-resolved", failed: "pill-status-closed", cancelled: "pill-status-closed",
};

function upsertStep(steps, stepIndex, action, status) {
  const others = steps.filter((s) => s.step_index !== stepIndex);
  return [...others, { step_index: stepIndex, action, status }].sort((a, b) => a.step_index - b.step_index);
}

function reduceEvent(executions, envelope) {
  const { event_type, data } = envelope;
  const id = data.execution_id;
  if (!id) return executions;

  const existing = executions.find((e) => e.id === id) ||
    { id, playbookName: data.playbook_name || "Playbook", incidentId: data.incident_id, status: "running", steps: [] };
  const others = executions.filter((e) => e.id !== id);
  const updated = { ...existing, steps: existing.steps };

  switch (event_type) {
    case "playbook.started":
      updated.playbookName = data.playbook_name || updated.playbookName;
      updated.incidentId = data.incident_id ?? updated.incidentId;
      updated.status = "running";
      break;
    case "playbook.action_started":
      updated.steps = upsertStep(updated.steps, data.step_index, data.action, "running");
      break;
    case "playbook.action_completed":
      updated.steps = upsertStep(updated.steps, data.step_index, data.action, data.status || "completed");
      break;
    case "playbook.action_failed":
      updated.steps = upsertStep(updated.steps, data.step_index, data.action, "failed");
      break;
    case "playbook.approval_required":
      updated.status = "awaiting_approval";
      updated.steps = upsertStep(updated.steps, data.step_index, data.action, "awaiting_approval");
      break;
    case "playbook.completed":
      updated.status = "completed";
      break;
    case "playbook.failed":
      updated.status = "failed";
      updated.error = data.error;
      break;
    case "playbook.cancelled":
      updated.status = "cancelled";
      break;
    default:
      return executions;
  }

  return [updated, ...others].slice(0, MAX_EXECUTIONS);
}

export default function PlaybookActivity() {
  const [executions, setExecutions] = useState([]);
  const handler = (envelope) => setExecutions((prev) => reduceEvent(prev, envelope));

  useRealtime("playbook.started", handler);
  useRealtime("playbook.action_started", handler);
  useRealtime("playbook.action_completed", handler);
  useRealtime("playbook.action_failed", handler);
  useRealtime("playbook.approval_required", handler);
  useRealtime("playbook.completed", handler);
  useRealtime("playbook.failed", handler);
  useRealtime("playbook.cancelled", handler);

  return (
    <div className="panel">
      <h3>Playbook Activity</h3>
      {executions.length === 0 ? (
        <p className="enrichment-empty">No playbook activity yet.</p>
      ) : (
        executions.map((ex) => (
          <div key={ex.id} className="playbook-activity-item">
            <div className="playbook-activity-header">
              <strong>{ex.playbookName}</strong>
              <span className={`pill ${STATUS_PILL[ex.status] || ""}`}>{ex.status.replace("_", " ")}</span>
            </div>
            <ul className="playbook-step-list">
              {ex.steps.map((s) => (
                <li key={s.step_index}>
                  <span className="step-icon">{STEP_ICON[s.status] || "•"}</span> {s.action}
                  {s.status === "awaiting_approval" && <em> — awaiting approval</em>}
                </li>
              ))}
            </ul>
          </div>
        ))
      )}
    </div>
  );
}
