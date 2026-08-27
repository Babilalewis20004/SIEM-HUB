import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getLogs, uploadLogs } from "../api/client";

export default function Logs() {
  const [search, setSearch] = useState("");
  const [file, setFile] = useState(null);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["logs", search],
    queryFn: () => getLogs({ q: search || undefined, per_page: 50 }),
  });

  const uploadMutation = useMutation({
    mutationFn: (formData) => uploadLogs(formData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      setFile(null);
    },
  });

  const handleUpload = () => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    uploadMutation.mutate(formData);
  };

  return (
    <div>
      <h2>Log Explorer</h2>

      <div className="panel">
        <h3>Upload Log File</h3>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={handleUpload} disabled={!file || uploadMutation.isPending}>
          {uploadMutation.isPending ? "Uploading…" : "Upload"}
        </button>
        {uploadMutation.isSuccess && <span> Ingested {uploadMutation.data.ingested} lines.</span>}
      </div>

      <input
        className="search-input"
        placeholder="Search raw log messages…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th><th>Source</th><th>Type</th><th>Severity</th><th>IP</th><th>Message</th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((log) => (
              <tr key={log.id}>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.source}</td>
                <td>{log.event_type}</td>
                <td>{log.severity}</td>
                <td>{log.source_ip || "—"}</td>
                <td className="raw-msg">{log.raw_message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
