// "Is detection actually running" trust signal (see /api/stats/summary's
// detection_status) -- reuses the same dot+label pattern as
// ConnectionStatus.jsx for visual consistency, mapped onto whichever of the
// three dot colors best fits: green only when a scheduled job has
// completed recently, red when it's actively failed or the scheduler is
// off, yellow for the in-between "not proven broken, not proven fine" states.
const STATUS_MAP = {
  healthy: { dot: "live", label: "Detection running" },
  stale: { dot: "reconnecting", label: "Detection stale" },
  unknown: { dot: "reconnecting", label: "Detection starting up" },
  failed: { dot: "offline", label: "Detection failed" },
  disabled: { dot: "offline", label: "Detection disabled" },
};

function timeAgo(isoString) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(isoString).getTime()) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

export default function DetectionStatus({ status }) {
  if (!status) return null;
  const { dot, label } = STATUS_MAP[status.state] ?? { dot: "offline", label: status.state };

  return (
    <div
      className={`connection-status detection-status status-${dot}`}
      title={status.last_run_at ? `Last scheduled run: ${new Date(status.last_run_at).toLocaleString()}` : "No scheduled run recorded yet"}
    >
      <span className="connection-dot" />
      {label}
      {status.last_run_at && ` · ${timeAgo(status.last_run_at)}`}
    </div>
  );
}
