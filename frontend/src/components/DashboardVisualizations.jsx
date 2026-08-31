import { useMemo, useState } from "react";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Cell,
} from "recharts";

const TOOLTIP_STYLE = {
  background: "var(--panel)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text)",
  fontSize: 13,
};
const TOOLTIP_LABEL_STYLE = { color: "var(--muted)" };
const TOOLTIP_CURSOR = { fill: "rgba(255,255,255,0.04)" };

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const ALERT_SEVERITY_ORDER = ["info", "warning", "critical"];
const OUTCOME_ORDER = ["success", "failure", "blocked", "denied", "unknown"];

const STATUS_COLORS = {
  info: "var(--stat-neutral)",
  low: "var(--stat-good)",
  success: "var(--stat-good)",
  medium: "var(--stat-warn)",
  warning: "var(--stat-warn)",
  high: "var(--stat-serious)",
  blocked: "var(--stat-serious)",
  denied: "var(--stat-serious)",
  critical: "var(--stat-bad)",
  failure: "var(--stat-bad)",
  unknown: "var(--stat-neutral)",
};

const TACTIC_COLORS = [
  "var(--series-1)", "var(--series-2)", "var(--series-3)", "var(--series-4)",
  "var(--series-5)", "var(--series-6)", "var(--series-7)", "var(--series-8)",
];

// Fixed-order keys first (so severity/outcome always read low->high, left to
// right in the underlying dict order), then anything unexpected the schema
// gains later, sorted by count so it doesn't just vanish.
function orderedEntries(counts, order) {
  const known = order.filter((k) => (counts?.[k] ?? 0) > 0);
  const rest = Object.keys(counts ?? {})
    .filter((k) => !order.includes(k))
    .sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0));
  return [...known, ...rest].map((k) => ({ name: k, count: counts[k] }));
}

function sortedEntries(counts) {
  return Object.entries(counts ?? {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

function EmptyState() {
  return <div className="viz-empty">No data yet</div>;
}

function CategoryBarChart({ data, color = "var(--accent)", colorByKey }) {
  if (!data.length) return <EmptyState />;
  return (
    <ResponsiveContainer width="100%" height={Math.max(220, data.length * 36)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
        <XAxis type="number" stroke="var(--muted)" allowDecimals={false} fontSize={12} />
        <YAxis type="category" dataKey="name" stroke="var(--muted)" width={140} fontSize={12} />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} cursor={TOOLTIP_CURSOR} />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={28}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={colorByKey ? colorByKey(entry.name) : color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function TimeseriesChart({ series, lines }) {
  if (!series.length) return <EmptyState />;
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={series}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
        <XAxis dataKey="bucket" tickFormatter={(v) => v.slice(11, 16)} stroke="var(--muted)" fontSize={12} />
        <YAxis stroke="var(--muted)" fontSize={12} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} cursor={TOOLTIP_CURSOR} />
        {lines.map((line) => (
          <Line key={line.dataKey} type="monotone" dataKey={line.dataKey} stroke={line.color}
                strokeWidth={line.width ?? 2} dot={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

function Legend({ items }) {
  return (
    <div className="viz-legend">
      {items.map((item) => (
        <span className="viz-legend-item" key={item.label}>
          <span className="viz-legend-swatch" style={{ background: item.color }} />
          {item.label}
        </span>
      ))}
    </div>
  );
}

function MitreChart({ counts }) {
  const tactics = useMemo(
    () => [...new Set((counts ?? []).map((c) => c.tactic))].sort(),
    [counts]
  );
  const tacticColor = (tactic) => TACTIC_COLORS[tactics.indexOf(tactic) % TACTIC_COLORS.length];
  const data = [...(counts ?? [])]
    .sort((a, b) => b.count - a.count)
    .map((c) => ({ name: `${c.technique_id} ${c.name}`, count: c.count, tactic: c.tactic }));

  if (!data.length) {
    return <div className="viz-empty">No alerts mapped to MITRE ATT&amp;CK techniques yet</div>;
  }

  return (
    <>
      <CategoryBarChart data={data} colorByKey={(name) => {
        const row = data.find((d) => d.name === name);
        return tacticColor(row?.tactic);
      }} />
      <Legend items={tactics.map((t, i) => ({ label: t, color: TACTIC_COLORS[i % TACTIC_COLORS.length] }))} />
    </>
  );
}

const TABS = [
  {
    key: "volume",
    label: "Event Volume",
    render: ({ timeseries }) => (
      <TimeseriesChart
        series={timeseries?.series ?? []}
        lines={[
          { dataKey: "total", color: "var(--accent)", width: 2 },
          { dataKey: "medium", color: "var(--stat-warn)", width: 2 },
          { dataKey: "high", color: "var(--stat-serious)", width: 1.5 },
          { dataKey: "critical", color: "var(--stat-bad)", width: 2 },
        ]}
      />
    ),
  },
  {
    key: "severity",
    label: "Events by Severity",
    render: ({ summary }) => (
      <CategoryBarChart
        data={orderedEntries(summary?.events_by_severity, SEVERITY_ORDER)}
        colorByKey={(k) => STATUS_COLORS[k] ?? "var(--accent)"}
      />
    ),
  },
  {
    key: "alert-severity",
    label: "Open Alerts by Severity",
    render: ({ summary }) => (
      <CategoryBarChart
        data={orderedEntries(summary?.alert_severity_counts, ALERT_SEVERITY_ORDER)}
        colorByKey={(k) => STATUS_COLORS[k] ?? "var(--accent)"}
      />
    ),
  },
  {
    key: "category",
    label: "Events by Category",
    render: ({ summary }) => <CategoryBarChart data={sortedEntries(summary?.events_by_category)} />,
  },
  {
    key: "type",
    label: "Events by Type",
    render: ({ summary }) => <CategoryBarChart data={sortedEntries(summary?.events_by_type)} />,
  },
  {
    key: "source-type",
    label: "Events by Source Type",
    render: ({ summary }) => <CategoryBarChart data={sortedEntries(summary?.events_by_source_type)} />,
  },
  {
    key: "outcome",
    label: "Events by Outcome",
    render: ({ summary }) => (
      <CategoryBarChart
        data={orderedEntries(summary?.events_by_outcome, OUTCOME_ORDER)}
        colorByKey={(k) => STATUS_COLORS[k] ?? "var(--accent)"}
      />
    ),
  },
  {
    key: "top-ips",
    label: "Top Source IPs",
    render: ({ summary }) => (
      <CategoryBarChart
        data={(summary?.top_source_ips ?? []).map((row) => ({ name: row.ip, count: row.count }))}
      />
    ),
  },
  {
    key: "country",
    label: "Events by Country",
    render: ({ summary }) => <CategoryBarChart data={sortedEntries(summary?.events_by_country)} />,
  },
  {
    key: "mitre",
    label: "MITRE ATT&CK",
    render: ({ summary }) => <MitreChart counts={summary?.mitre_technique_counts} />,
  },
  {
    key: "ioc",
    label: "IOC Matches Over Time",
    render: ({ iocTimeseries }) => (
      <TimeseriesChart
        series={iocTimeseries?.series ?? []}
        lines={[{ dataKey: "count", color: "var(--stat-bad)", width: 2 }]}
      />
    ),
  },
];

export default function DashboardVisualizations({ summary, timeseries, iocTimeseries }) {
  const [active, setActive] = useState(TABS[0].key);
  const activeTab = TABS.find((t) => t.key === active) ?? TABS[0];

  return (
    <div className="panel">
      <h3>Visualizations</h3>
      <div className="viz-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`viz-tab${tab.key === active ? " active" : ""}`}
            onClick={() => setActive(tab.key)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>
      {activeTab.render({ summary, timeseries, iocTimeseries })}
    </div>
  );
}
