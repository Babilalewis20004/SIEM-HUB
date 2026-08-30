// Normalises the various severity/status vocabularies in this app (Alert:
// info|warning|critical, Incident: info|low|medium|high|critical, IOC
// threat_level: unknown|low|medium|high|critical) down to the four levels
// index.css's .risk-* classes style, so realtime components can share one
// color scale without inventing new CSS.
const MAP = { info: "low", low: "low", warning: "medium", medium: "medium", high: "high", critical: "critical" };

export function normalizeSeverity(value) {
  return MAP[(value || "").toLowerCase()] || "medium";
}
