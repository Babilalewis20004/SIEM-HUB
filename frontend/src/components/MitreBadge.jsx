// Reusable MITRE ATT&CK technique chip. Used on the Alerts table, incident
// detail, and incident summaries wherever a technique needs to be shown
// consistently ({technique_id, name, tactic} — see Alert.to_dict()'s
// "mitre" field and Incident.enrichment_summary() on the backend).
export default function MitreBadge({ technique }) {
  if (!technique) return null;
  const { technique_id: id, name, tactic } = technique;

  return (
    <span className="mitre-chip" title={name}>
      <a
        href={`https://attack.mitre.org/techniques/${id.split(".")[0]}/`}
        target="_blank"
        rel="noreferrer"
        onClick={(e) => e.stopPropagation()}
      >
        {id}
      </a>
      {name && <span>{name}</span>}
      {tactic && <span className="mitre-tactic">({tactic})</span>}
    </span>
  );
}

export function MitreBadgeList({ techniques }) {
  if (!techniques || techniques.length === 0) {
    return <span className="enrichment-empty">No MITRE ATT&CK mapping.</span>;
  }
  return (
    <div>
      {techniques.map((t) => (
        <MitreBadge key={t.technique_id} technique={t} />
      ))}
    </div>
  );
}
