import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { getSummary, getTimeseries } from "../api/client";
import { useRealtime } from "../hooks/useRealtime.js";
import LiveAlertFeed from "../components/LiveAlertFeed.jsx";
import PlaybookActivity from "../components/PlaybookActivity.jsx";

function StatCard({ label, value, tone = "default" }) {
  return (
    <div className={`stat-card tone-${tone}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// Real-time SOC widgets (Part 15). The REST /api/stats/summary snapshot is
// the source of truth on page load / every 15s poll; WebSocket events just
// invalidate it early so a fresh alert/incident/playbook change shows up
// without waiting for the next poll tick.
export default function Dashboard() {
  const queryClient = useQueryClient();
  const { data: summary } = useQuery({ queryKey: ["summary"], queryFn: getSummary });
  const { data: ts } = useQuery({ queryKey: ["timeseries"], queryFn: () => getTimeseries(24) });

  const refreshSummary = () => queryClient.invalidateQueries({ queryKey: ["summary"] });
  useRealtime("alert.created", refreshSummary);
  useRealtime("alert.updated", refreshSummary);
  useRealtime("incident.created", refreshSummary);
  useRealtime("incident.status_changed", refreshSummary);
  useRealtime("ioc.match", refreshSummary);
  useRealtime("playbook.started", refreshSummary);
  useRealtime("playbook.completed", refreshSummary);
  useRealtime("playbook.failed", refreshSummary);
  useRealtime("playbook.cancelled", refreshSummary);

  return (
    <div>
      <h2>Dashboard</h2>

      <div className="stat-grid">
        <StatCard label="Active Incidents" value={summary?.active_incidents ?? "—"} tone="warning" />
        <StatCard label="Open Alerts" value={summary?.open_alerts ?? "—"} tone="warning" />
        <StatCard label="Critical Alerts" value={summary?.critical_alerts ?? 0} tone="critical" />
        <StatCard label="Events / minute" value={summary?.events_per_minute ?? 0} />
        <StatCard label="High-risk IOC Matches" value={summary?.high_risk_ioc_matches ?? 0} tone="critical" />
        <StatCard label="Playbooks Running" value={summary?.playbooks_running ?? 0} />
      </div>

      <LiveAlertFeed />
      <PlaybookActivity />

      <div className="panel">
        <h3>Event Volume (last 24h)</h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={ts?.series ?? []}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="bucket" tickFormatter={(v) => v.slice(11, 16)} />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="total" stroke="#4f8cff" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="medium" stroke="#f5a623" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="high" stroke="#e6493d" strokeWidth={1.5} dot={false} />
            <Line type="monotone" dataKey="critical" stroke="#e6493d" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="panel">
        <h3>Events by Category</h3>
        <table className="data-table">
          <thead>
            <tr><th>Category</th><th>Event Count</th></tr>
          </thead>
          <tbody>
            {Object.entries(summary?.events_by_category ?? {}).map(([category, count]) => (
              <tr key={category}>
                <td>{category}</td>
                <td>{count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Top Source IPs</h3>
        <table className="data-table">
          <thead>
            <tr><th>IP</th><th>Event Count</th></tr>
          </thead>
          <tbody>
            {(summary?.top_source_ips ?? []).map((row) => (
              <tr key={row.ip}>
                <td>{row.ip}</td>
                <td>{row.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
