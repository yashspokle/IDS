import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

const navItems = [
  { id: "overview", label: "Overview", icon: "▦" },
  { id: "alerts", label: "Security Alerts", icon: "!" },
  { id: "traffic", label: "Network Traffic", icon: "⌁" },
  { id: "engine", label: "Detection Engine", icon: "◈" },
];

const severityClass = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

function getActivityData(alerts) {
  const buckets = Array(12).fill(0);

  alerts.slice(0, 100).forEach((alert) => {
    const minute = new Date(alert.timestamp).getMinutes();
    buckets[minute % 12]++;
  });

  return buckets;
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [activePage, setActivePage] = useState("overview");
  const [apiStatus, setApiStatus] = useState("checking");

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${API}/api/alerts`);

        if (!response.ok) {
          throw new Error("API error");
        }

        const data = await response.json();

        setAlerts(data);
        setApiStatus("online");
      } catch {
        setApiStatus("offline");
      }
    };

    fetchAlerts();

    const interval = setInterval(fetchAlerts, 5000);

    return () => clearInterval(interval);
  }, []);

  const stats = useMemo(() => {
    const threats = alerts.filter(
      (a) => a.attack !== "Normal"
    );

    const highRisk = alerts.filter(
      (a) =>
        a.severity === "HIGH" ||
        a.severity === "CRITICAL"
    );

    const avgConfidence =
      alerts.length > 0
        ? alerts.reduce(
            (sum, a) => sum + Number(a.confidence || 0),
            0
          ) / alerts.length
        : 0;

    return {
      total: alerts.length,
      threats: threats.length,
      normal: alerts.length - threats.length,
      highRisk: highRisk.length,
      confidence: avgConfidence,
    };
  }, [alerts]);

  const attackCounts = useMemo(() => {
    const counts = {};

    alerts.forEach((alert) => {
      counts[alert.attack] =
        (counts[alert.attack] || 0) + 1;
    });

    return counts;
  }, [alerts]);

  const activity = useMemo(
    () => getActivityData(alerts),
    [alerts]
  );

  const latestAlert = alerts[0];

  return (
    <div className="app">

      {/* SIDEBAR */}
      <aside className="sidebar">

        <div className="brand">
          

          <div>
            <div className="brand-name">INTRUSION DETECTION SYSTEM</div>
            
          </div>
        </div>

        <div className="nav-section">
          <div className="nav-label">MONITORING</div>

          {navItems.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${
                activePage === item.id ? "active" : ""
              }`}
              onClick={() => setActivePage(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        <div className="sidebar-bottom">

          <div className="system-title">
            SYSTEM STATUS
          </div>

          <StatusRow
            label="Packet Capture"
            active
          />

          <StatusRow
            label="Detection API"
            active={apiStatus === "online"}
          />

          <StatusRow
            label="Database"
            active={apiStatus === "online"}
          />

          <div className="version">
            IDS · v1.0
          </div>

        </div>
      </aside>

      {/* MAIN */}
      <main className="main">

        <header className="topbar">

          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS CENTER
            </div>

            <h1>
              {activePage === "overview" &&
                "Network Security Overview"}

              {activePage === "alerts" &&
                "Security Alerts"}

              {activePage === "traffic" &&
                "Network Traffic"}

              {activePage === "engine" &&
                "Detection Engine"}
            </h1>
          </div>

          <div className="top-status">

            <div className="live-status">
              <span className="live-dot" />
              LIVE CAPTURE
            </div>

            <div
              className={`api-status ${
                apiStatus === "online"
                  ? "online"
                  : "offline"
              }`}
            >
              API{" "}
              {apiStatus === "online"
                ? "ONLINE"
                : "OFFLINE"}
            </div>

          </div>
        </header>

        {activePage === "overview" && (
          <OverviewPage
            stats={stats}
            alerts={alerts}
            attackCounts={attackCounts}
            activity={activity}
          />
        )}

        {activePage === "alerts" && (
          <AlertsPage alerts={alerts} />
        )}

        {activePage === "traffic" && (
          <TrafficPage
            alerts={alerts}
            activity={activity}
          />
        )}

        {activePage === "engine" && (
          <DetectionPage
            stats={stats}
          />
        )}

        <footer>
          <span>NETWORK INTRUSION DETECTION SYSTEM</span>
          <span>
            RANDOM FOREST · NSL-KDD · SCAPY
          </span>
        </footer>

      </main>
    </div>
  );
}


/* =========================
   OVERVIEW
========================= */

function OverviewPage({
  stats,
  alerts,
  attackCounts,
  activity,
}) {
  return (
    <>

      <section className="metrics">

        <MetricCard
          label="Total Events"
          value={stats.total}
          detail="Captured flows"
        />

        <MetricCard
          label="Detected Threats"
          value={stats.threats}
          detail="Non-normal classifications"
          danger={stats.threats > 0}
        />

        <MetricCard
          label="Normal Traffic"
          value={stats.normal}
          detail="Benign classifications"
        />

        <MetricCard
          label="High Risk Events"
          value={stats.highRisk}
          detail="High / critical severity"
          danger={stats.highRisk > 0}
        />

      </section>

      <section className="dashboard-grid">

        <ActivityPanel activity={activity} />

        <ThreatPanel
          attackCounts={attackCounts}
          total={stats.total}
        />

      </section>

      <section className="panel">

        <PanelHeader
          title="Recent Security Events"
          subtitle="Latest classified network flows"
        />

        <AlertsTable alerts={alerts.slice(0, 8)} />

      </section>

    </>
  );
}


/* =========================
   ALERTS
========================= */

function AlertsPage({ alerts }) {
  return (
    <section className="panel page-panel">

      <PanelHeader
        title="Security Alerts"
        subtitle={`${alerts.length} events recorded`}
      />

      <AlertsTable alerts={alerts} />

    </section>
  );
}


/* =========================
   TRAFFIC
========================= */

function TrafficPage({
  alerts,
  activity,
}) {
  const sources = [
    ...new Set(
      alerts
        .filter((a) => a.source_ip)
        .map((a) => a.source_ip)
    ),
  ];

  return (
    <>

      <section className="dashboard-grid">

        <ActivityPanel activity={activity} />

        <div className="panel traffic-summary">

          <PanelHeader
            title="Traffic Summary"
            subtitle="Observed endpoints"
          />

          <div className="traffic-number">
            {sources.length}
          </div>

          <div className="traffic-caption">
            Unique source endpoints
          </div>

        </div>

      </section>

      <section className="panel">

        <PanelHeader
          title="Observed Network Flows"
          subtitle="Recently captured endpoints"
        />

        <div className="endpoint-list">

          {alerts.slice(0, 15).map((alert) => (
            <div
              className="endpoint-row"
              key={alert.id}
            >

              <div className="endpoint-time">
                {alert.timestamp}
              </div>

              <div className="endpoint-ip">
                {alert.source_ip}
              </div>

              <div className="endpoint-arrow">
                →
              </div>

              <div className="endpoint-ip">
                {alert.destination_ip}
              </div>

              <div
                className={`severity ${severityClass[alert.severity] || "low"}`}
              >
                {alert.severity}
              </div>

            </div>
          ))}

        </div>

      </section>

    </>
  );
}


/* =========================
   DETECTION ENGINE
========================= */

function DetectionPage({ stats }) {
  return (
    <>

      <section className="engine-header">

        <div>
          <div className="eyebrow">
            DETECTION PIPELINE
          </div>

          <h2>
            Random Forest Detection Engine
          </h2>

          <p>
            Network flows are captured, transformed
            into features and classified against the
            NSL-KDD attack families.
          </p>
        </div>

        <div className="engine-status">
          <span className="status-dot" />
          ENGINE ACTIVE
        </div>

      </section>

      <section className="engine-grid">

        <EngineCard
          title="Packet Capture"
          value="Scapy"
          description="Live TCP and UDP traffic capture"
        />

        <EngineCard
          title="Dataset"
          value="NSL-KDD"
          description="Network intrusion classification dataset"
        />

        <EngineCard
          title="Classifier"
          value="Random Forest"
          description="150-tree ensemble classification model"
        />

        <EngineCard
          title="Events Processed"
          value={stats.total}
          description="Flows classified by the engine"
        />

      </section>

      <section className="panel pipeline-panel">

        <PanelHeader
          title="Detection Pipeline"
          subtitle="Live processing architecture"
        />

        <div className="pipeline">

          <PipelineNode
            title="Network"
            subtitle="Packets"
          />

          <PipelineArrow />

          <PipelineNode
            title="Scapy"
            subtitle="Capture"
          />

          <PipelineArrow />

          <PipelineNode
            title="Flow"
            subtitle="Features"
          />

          <PipelineArrow />

          <PipelineNode
            title="Random Forest"
            subtitle="Classification"
          />

          <PipelineArrow />

          <PipelineNode
            title="Alert"
            subtitle="Severity"
          />

          <PipelineArrow />

          <PipelineNode
            title="SQLite"
            subtitle="Storage"
          />

        </div>

      </section>

    </>
  );
}


/* =========================
   COMPONENTS
========================= */

function StatusRow({ label, active }) {
  return (
    <div className="status-row">

      <span
        className={`status-dot ${
          active ? "active" : "inactive"
        }`}
      />

      <span>{label}</span>

      <span className="status-state">
        {active ? "ON" : "OFF"}
      </span>

    </div>
  );
}


function MetricCard({
  label,
  value,
  detail,
  danger,
}) {
  return (
    <div className="metric-card">

      <div className="metric-top">

        <span>{label}</span>

        <span
          className={`metric-indicator ${
            danger ? "danger" : ""
          }`}
        />

      </div>

      <div className="metric-value">
        {value}
      </div>

      <div className="metric-detail">
        {detail}
      </div>

    </div>
  );
}


function PanelHeader({
  title,
  subtitle,
}) {
  return (
    <div className="panel-header">

      <div>
        <h3>{title}</h3>
        <p>{subtitle}</p>
      </div>

      <span className="panel-line" />

    </div>
  );
}


function ActivityPanel({ activity }) {
  const max = Math.max(...activity, 1);

  const points = activity
    .map((value, index) => {

      const x = 10 + index * 34;

      const y =
        125 - (value / max) * 95;

      return `${x},${y}`;

    })
    .join(" ");

  return (
    <div className="panel activity-panel">

      <PanelHeader
        title="Network Activity"
        subtitle="Recent flow volume"
      />

      <div className="chart">

        <svg
          viewBox="0 0 390 140"
          preserveAspectRatio="none"
        >

          <line
            x1="10"
            y1="125"
            x2="380"
            y2="125"
            className="chart-grid"
          />

          <line
            x1="10"
            y1="75"
            x2="380"
            y2="75"
            className="chart-grid"
          />

          <line
            x1="10"
            y1="25"
            x2="380"
            y2="25"
            className="chart-grid"
          />

          <polyline
            points={points}
            className="activity-line"
          />

        </svg>

      </div>

      <div className="chart-labels">
        <span>12 min ago</span>
        <span>Now</span>
      </div>

    </div>
  );
}


function ThreatPanel({
  attackCounts,
  total,
}) {
  const normal = attackCounts.Normal || 0;

  const threats = total - normal;

  const percentage =
    total > 0
      ? Math.round((threats / total) * 100)
      : 0;

  return (
    <div className="panel threat-panel">

      <PanelHeader
        title="Threat Distribution"
        subtitle="Classification breakdown"
      />

      <div className="threat-content">

        <div className="threat-ring">

          <div>
            <strong>{percentage}%</strong>
            <span>Threats</span>
          </div>

        </div>

        <div className="attack-list">

          {Object.entries(attackCounts).map(
            ([name, count]) => {

              const percent =
                total > 0
                  ? Math.round(
                      (count / total) * 100
                    )
                  : 0;

              return (
                <div
                  className="attack-item"
                  key={name}
                >

                  <div className="attack-info">
                    <span>{name}</span>
                    <span>{count}</span>
                  </div>

                  <div className="attack-bar">
                    <span
                      style={{
                        width: `${percent}%`,
                      }}
                    />
                  </div>

                </div>
              );
            }
          )}

        </div>

      </div>

    </div>
  );
}


function AlertsTable({ alerts }) {
  if (!alerts.length) {
    return (
      <div className="empty-state">
        No security events recorded yet.
      </div>
    );
  }

  return (
    <div className="table-wrapper">

      <table>

        <thead>
          <tr>
            <th>TIME</th>
            <th>SOURCE</th>
            <th>DESTINATION</th>
            <th>CLASSIFICATION</th>
            <th>CONFIDENCE</th>
            <th>SEVERITY</th>
          </tr>
        </thead>

        <tbody>

          {alerts.map((alert) => (

            <tr key={alert.id}>

              <td className="muted">
                {alert.timestamp}
              </td>

              <td className="mono">
                {alert.source_ip}
              </td>

              <td className="mono">
                {alert.destination_ip}
              </td>

              <td>
                <span
                  className={
                    alert.attack === "Normal"
                      ? "classification normal"
                      : "classification threat"
                  }
                >
                  {alert.attack}
                </span>
              </td>

              <td>
                {Number(alert.confidence).toFixed(2)}%
              </td>

              <td>
                <span
                  className={`severity ${
                    severityClass[alert.severity] ||
                    "low"
                  }`}
                >
                  {alert.severity}
                </span>
              </td>

            </tr>

          ))}

        </tbody>

      </table>

    </div>
  );
}


function EngineCard({
  title,
  value,
  description,
}) {
  return (
    <div className="engine-card">

      <div className="engine-label">
        {title}
      </div>

      <div className="engine-value">
        {value}
      </div>

      <div className="engine-description">
        {description}
      </div>

    </div>
  );
}


function PipelineNode({
  title,
  subtitle,
}) {
  return (
    <div className="pipeline-node">

      <strong>{title}</strong>
      <span>{subtitle}</span>

    </div>
  );
}


function PipelineArrow() {
  return (
    <div className="pipeline-arrow">
      →
    </div>
  );
}


export default App;