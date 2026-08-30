import { useState } from "react";
import { useRealtime } from "../hooks/useRealtime.js";
import { normalizeSeverity } from "../utils/severity.js";

// Retains at most this many entries in the browser (Part 16 -- "limit the
// number retained to prevent unbounded memory growth"). This is a live
// feed, not a data source: history lives in the REST /api/alerts endpoint.
const MAX_ITEMS = 25;

function prepend(prev, item) {
  return [item, ...prev].slice(0, MAX_ITEMS);
}

export default function LiveAlertFeed() {
  const [items, setItems] = useState([]);

  useRealtime("alert.created", (envelope) => {
    const d = envelope.data;
    setItems((prev) => prepend(prev, {
      id: `alert-${d.id}`,
      time: envelope.timestamp,
      severity: normalizeSeverity(d.severity),
      title: d.title,
      detail: d.detection_source ? `${d.detection_source} detection` : null,
    }));
  });

  useRealtime("ioc.match", (envelope) => {
    const d = envelope.data;
    setItems((prev) => prepend(prev, {
      id: `ioc-${d.alert_id}-${d.indicator}`,
      time: envelope.timestamp,
      severity: normalizeSeverity(d.threat_level),
      title: `Known Malicious IOC: ${d.indicator}`,
      detail: `${d.indicator_type} · ${(d.threat_level || "unknown").toUpperCase()}`,
    }));
  });

  return (
    <div className="panel">
      <h3>Live Security Activity</h3>
      {items.length === 0 ? (
        <p className="enrichment-empty">Waiting for activity…</p>
      ) : (
        <div className="live-feed">
          {items.map((item) => (
            <div key={item.id} className="live-feed-item">
              <span className="live-feed-time">{new Date(item.time).toLocaleTimeString()}</span>
              <span className={`risk-badge risk-${item.severity}`}>{item.severity}</span>
              <span className="live-feed-title">{item.title}</span>
              {item.detail && <span className="live-feed-detail">{item.detail}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
