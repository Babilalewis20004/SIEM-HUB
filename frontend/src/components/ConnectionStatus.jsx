import { useRealtimeStatus } from "../context/RealtimeContext.jsx";

const LABELS = { live: "Live", reconnecting: "Reconnecting…", offline: "Offline" };

// Small, deliberately non-dominant SOC connection indicator (Part 13) --
// sits in the sidebar footer next to the user chip, not the header.
export default function ConnectionStatus() {
  const status = useRealtimeStatus();
  return (
    <div className={`connection-status status-${status}`} title={`Realtime connection: ${LABELS[status] ?? status}`}>
      <span className="connection-dot" />
      {LABELS[status] ?? status}
    </div>
  );
}
