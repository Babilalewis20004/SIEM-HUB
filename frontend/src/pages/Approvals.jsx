import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getPlaybookExecutions, approveExecution, rejectExecution } from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";
import { useRealtime } from "../hooks/useRealtime.js";

export default function Approvals() {
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["playbook-executions", { status: "awaiting_approval" }],
    queryFn: () => getPlaybookExecutions({ status: "awaiting_approval" }),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["playbook-executions"] });
  useRealtime("playbook.approval_required", invalidate);
  useRealtime("playbook.completed", invalidate);
  useRealtime("playbook.failed", invalidate);

  const approveMutation = useMutation({ mutationFn: approveExecution, onSuccess: invalidate });
  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }) => rejectExecution(id, reason),
    onSuccess: invalidate,
  });

  const handleApprove = (execution, approval) => {
    const ok = window.confirm(
      `Approve "${approval.action}" (${approval.risk_level.toUpperCase()} risk)?\n\n` +
      `Parameters: ${JSON.stringify(approval.parameters)}\n\n` +
      "This will execute a real response action (currently simulated by the mock provider)."
    );
    if (ok) approveMutation.mutate(execution.id);
  };

  const handleReject = (execution) => {
    const reason = window.prompt("Reason for rejecting this action (optional):", "");
    if (reason !== null) rejectMutation.mutate({ id: execution.id, reason });
  };

  const executions = data?.items ?? [];

  return (
    <div>
      <h2>Response Approvals</h2>
      {isLoading ? (
        <p>Loading…</p>
      ) : executions.length === 0 ? (
        <p className="enrichment-empty">No response actions are awaiting approval.</p>
      ) : (
        executions.map((execution) => {
          const approval = (execution.approvals ?? []).find((a) => a.status === "pending");
          if (!approval) return null;
          return (
            <div key={execution.id} className="panel">
              <div className="page-header">
                <h3>
                  <span className={`risk-badge risk-${approval.risk_level}`}>{approval.risk_level}</span>
                  {" "}{approval.action}
                </h3>
              </div>
              <dl className="detail-grid">
                <dt>Playbook</dt><dd>{execution.playbook_name}</dd>
                <dt>Parameters</dt><dd><code>{JSON.stringify(approval.parameters)}</code></dd>
                <dt>Incident</dt>
                <dd>
                  {execution.incident_id
                    ? <Link to={`/incidents/${execution.incident_id}`}>#{execution.incident_id.slice(0, 8)}</Link>
                    : "—"}
                </dd>
                <dt>Requested</dt><dd>{new Date(approval.requested_at).toLocaleString()}</dd>
              </dl>
              {can("playbooks.approve") ? (
                <div className="row-actions">
                  <button onClick={() => handleApprove(execution, approval)} disabled={approveMutation.isPending}>
                    Approve
                  </button>
                  <button onClick={() => handleReject(execution)} disabled={rejectMutation.isPending}>
                    Reject
                  </button>
                </div>
              ) : (
                <p className="enrichment-empty">Only an admin who did not request this action may approve or reject it.</p>
              )}
            </div>
          );
        })
      )}
      {(approveMutation.isError || rejectMutation.isError) && (
        <p className="auth-error">
          {(approveMutation.error || rejectMutation.error)?.response?.data?.error}
        </p>
      )}
    </div>
  );
}
