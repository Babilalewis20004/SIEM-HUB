import { useQuery } from "@tanstack/react-query";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { getSummary, getTimeseries } from "../api/client";

function StatCard({ label, value, tone = "default" }) {
  return (
    <div className={`stat-card tone-${tone}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export default function Dashboard() {
  const { data: summary } = useQuery({ queryKey: ["summary"], queryFn: getSummary });
  const { data: ts } = useQuery({ queryKey: ["timeseries"], queryFn: () => getTimeseries(24) });

  return (
    <div>
      <h2>Dashboard</h2>

      <div className="stat-grid">
        <StatCard label="Total Logs" value={summary?.total_logs ?? "—"} />
        <StatCard label="Open Alerts" value={summary?.open_alerts ?? "—"} tone="warning" />
        <StatCard
          label="Critical Events"
          value={summary?.log_severity_counts?.critical ?? 0}
          tone="critical"
        />
        <StatCard
          label="Warning Events"
          value={summary?.log_severity_counts?.warning ?? 0}
          tone="warning"
        />
      </div>

      <div className="panel">
        <h3>Event Volume (last 24h)</h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={ts?.series ?? []}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="bucket" tickFormatter={(v) => v.slice(11, 16)} />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="total" stroke="#4f8cff" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="warning" stroke="#f5a623" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="critical" stroke="#e6493d" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
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
