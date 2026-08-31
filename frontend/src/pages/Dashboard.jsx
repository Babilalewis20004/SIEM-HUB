import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getSummary, getTimeseries, getIOCTimeseries } from "../api/client";
import { useRealtime } from "../hooks/useRealtime.js";
import LiveAlertFeed from "../components/LiveAlertFeed.jsx";
import PlaybookActivity from "../components/PlaybookActivity.jsx";
import DashboardVisualizations from "../components/DashboardVisualizations.jsx";
import DetectionStatus from "../components/DetectionStatus.jsx";

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
  const { data: iocTs } = useQuery({ queryKey: ["ioc-timeseries"], queryFn: () => getIOCTimeseries(24) });

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

      <DetectionStatus status={summary?.detection_status} />

      <LiveAlertFeed />
      <PlaybookActivity />

      <DashboardVisualizations summary={summary} timeseries={ts} iocTimeseries={iocTs} />
    </div>
  );
}
