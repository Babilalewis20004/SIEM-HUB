import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getPlaybooks, createPlaybook, deletePlaybook, executePlaybook } from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";
import Loading from "../components/Loading.jsx";
import ApiError from "../components/ApiError.jsx";

const TEMPLATE = JSON.stringify({
  name: "My Playbook",
  trigger_type: "manual",
  trigger_condition: {},
  steps: [
    { action: "add_incident_tag", parameters: { tag: "example" } },
    { action: "notify_analyst", parameters: { message: "Example playbook ran." } },
  ],
}, null, 2);

function CreatePlaybookForm({ onCreated }) {
  const [text, setText] = useState(TEMPLATE);
  const [parseError, setParseError] = useState(null);

  const mutation = useMutation({
    mutationFn: (definition) => createPlaybook(definition),
    onSuccess: () => {
      onCreated();
    },
  });

  const submit = () => {
    setParseError(null);
    try {
      const definition = JSON.parse(text);
      mutation.mutate(definition);
    } catch {
      setParseError("Invalid JSON.");
    }
  };

  return (
    <div className="panel import-panel">
      <h3>Create Playbook</h3>
      <p className="ml-status-line">
        Definition as JSON: name, trigger_type (manual/alert/incident), trigger_condition, and a
        steps list. Only registered actions are accepted -- see the action registry for names,
        required parameters, and risk levels.
      </p>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={12} />
      <button onClick={submit} disabled={mutation.isPending}>
        {mutation.isPending ? "Creating…" : "Create Playbook"}
      </button>
      {parseError && <p className="auth-error">{parseError}</p>}
      <ApiError mutations={mutation} />
    </div>
  );
}

export default function Playbooks() {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: playbooks, isLoading } = useQuery({ queryKey: ["playbooks"], queryFn: getPlaybooks });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["playbooks"] });

  const executeMutation = useMutation({
    mutationFn: (id) => executePlaybook(id, { mode: "manual" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["playbook-executions"] }),
  });
  const deleteMutation = useMutation({
    mutationFn: (id) => deletePlaybook(id),
    onSuccess: invalidate,
  });

  return (
    <div>
      <div className="page-header">
        <h2>Playbooks</h2>
        {can("playbooks.manage") && (
          <button onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? "Cancel" : "New Playbook"}
          </button>
        )}
      </div>

      {showCreate && (
        <CreatePlaybookForm onCreated={() => { setShowCreate(false); invalidate(); }} />
      )}

      {isLoading ? (
        <Loading />
      ) : (
        <table className="data-table">
          <thead>
            <tr><th>Name</th><th>Trigger</th><th>Status</th><th>Steps</th><th></th></tr>
          </thead>
          <tbody>
            {(playbooks ?? []).map((pb) => (
              <tr key={pb.id}>
                <td><Link to={`/playbooks/${pb.id}`}>{pb.name}</Link></td>
                <td>{pb.trigger_type}</td>
                <td>
                  <span className={`pill ${pb.enabled ? "pill-active" : "pill-inactive"}`}>
                    {pb.enabled ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td>{pb.steps.length}</td>
                <td className="row-actions">
                  {can("playbooks.execute") && pb.trigger_type === "manual" && (
                    <button
                      onClick={() => executeMutation.mutate(pb.id)}
                      disabled={executeMutation.isPending || !pb.enabled}
                    >
                      Execute
                    </button>
                  )}
                  {can("playbooks.manage") && (
                    <button
                      onClick={() => deleteMutation.mutate(pb.id)}
                      disabled={deleteMutation.isPending}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ApiError mutations={deleteMutation} />
    </div>
  );
}
