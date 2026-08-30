import { MitreBadgeList } from "./MitreBadge.jsx";

export function IocMatchList({ matches }) {
  if (!matches || matches.length === 0) {
    return <span className="enrichment-empty">No threat intelligence matches.</span>;
  }
  return (
    <div>
      {matches.map((m, i) => (
        <span className="ioc-chip" key={`${m.indicator}-${i}`}>
          <span className="ioc-indicator">{m.indicator}</span>
          <span className={`ioc-meta threat-${m.threat_level || "unknown"}`}>
            {(m.threat_level || "unknown").toUpperCase()}
            {m.confidence != null && ` · ${m.confidence}% confidence`}
          </span>
          <span className="ioc-meta">
            matched on {m.matched_field}
            {m.source && ` · ${m.source}`}
          </span>
        </span>
      ))}
    </div>
  );
}

export function RiskSummary({ risk }) {
  if (!risk) return null;
  return (
    <div>
      <span className={`risk-badge risk-${risk.overall_risk}`}>{risk.overall_risk} risk</span>
      <span className="ioc-meta" style={{ marginLeft: 8 }}>
        detection: {risk.detection_severity}
        {risk.ioc_threat_level && ` · IOC threat: ${risk.ioc_threat_level}`}
      </span>
    </div>
  );
}

// Shared "MITRE + IOC + risk" block used by the Alerts table's expandable
// row and the Incident detail page.
export default function EnrichmentPanel({ mitre, iocMatches, risk }) {
  return (
    <div className="enrichment-detail">
      {risk && (
        <div>
          <div className="enrichment-section-label">Risk</div>
          <RiskSummary risk={risk} />
        </div>
      )}
      <div>
        <div className="enrichment-section-label">MITRE ATT&CK</div>
        <MitreBadgeList techniques={mitre} />
      </div>
      <div>
        <div className="enrichment-section-label">Threat Intelligence</div>
        <IocMatchList matches={iocMatches} />
      </div>
    </div>
  );
}
