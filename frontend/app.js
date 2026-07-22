const API_BASE = "http://localhost:8000";
document.getElementById("api-base-label").textContent = API_BASE;

const statusEl = document.getElementById("conn-status");
const logsBody = document.querySelector("#logs-table tbody");
const blockedBody = document.querySelector("#blocked-table tbody");
const rulesBody = document.querySelector("#rules-table tbody");

let chart;
const chartData = { labels: [], benign: [], malicious: [] };

function initChart() {
  const ctx = document.getElementById("trafficChart").getContext("2d");
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: chartData.labels,
      datasets: [
        { label: "Benign", data: chartData.benign, borderColor: "#3fb27f", tension: 0.3, pointRadius: 0 },
        { label: "Malicious", data: chartData.malicious, borderColor: "#e5534b", tension: 0.3, pointRadius: 0 },
      ],
    },
    options: {
      responsive: true,
      scales: {
        x: { ticks: { color: "#8a97a6" }, grid: { color: "#1f2a37" } },
        y: { ticks: { color: "#8a97a6" }, grid: { color: "#1f2a37" }, beginAtZero: true },
      },
      plugins: { legend: { labels: { color: "#e6edf3" } } },
    },
  });
}

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString();
}

async function refreshStats() {
  const stats = await api("/api/stats");
  document.getElementById("stat-total").textContent = stats.total_flows;
  document.getElementById("stat-allowed").textContent = stats.allowed;
  document.getElementById("stat-blocked").textContent = stats.blocked;
  document.getElementById("stat-malicious").textContent = stats.malicious_detected;
  document.getElementById("stat-blocked-ips").textContent = stats.currently_blocked_ips;

  const now = new Date().toLocaleTimeString();
  chartData.labels.push(now);
  chartData.benign.push(stats.total_flows - stats.malicious_detected);
  chartData.malicious.push(stats.malicious_detected);
  if (chartData.labels.length > 20) {
    chartData.labels.shift(); chartData.benign.shift(); chartData.malicious.shift();
  }
  chart.update();
}

async function refreshLogs() {
  const logs = await api("/api/logs?limit=50");
  logsBody.innerHTML = logs.map(l => `
    <tr>
      <td>${fmtTime(l.timestamp)}</td>
      <td>${l.src_ip}</td>
      <td>${l.dst_ip ?? ""}</td>
      <td><span class="badge ${l.label}">${l.label}</span></td>
      <td>${(l.confidence * 100).toFixed(1)}%</td>
      <td><span class="badge ${l.verdict === "BLOCK" ? "block" : "allow"}">${l.verdict}</span></td>
      <td>${l.reason}</td>
    </tr>`).join("");
}

async function refreshBlocked() {
  const blocked = await api("/api/blocked");
  blockedBody.innerHTML = blocked.map(b => `
    <tr>
      <td>${b.ip}</td>
      <td>${fmtTime(b.blocked_at)}</td>
      <td>${b.reason}</td>
      <td><button class="small-btn" onclick="unblock('${b.ip}')">Unblock</button></td>
    </tr>`).join("");
}

async function refreshRules() {
  const rules = await api("/api/rules");
  rulesBody.innerHTML = rules.map(r => `
    <tr>
      <td>${r.rule_type}</td>
      <td>${r.value}</td>
      <td>${r.description || ""}</td>
      <td><button class="small-btn" onclick="deleteRule(${r.id})">Remove</button></td>
    </tr>`).join("");
}

window.unblock = async (ip) => {
  await api(`/api/blocked/${ip}/unblock`, { method: "POST" });
  refreshBlocked(); refreshStats();
};

window.deleteRule = async (id) => {
  await api(`/api/rules/${id}`, { method: "DELETE" });
  refreshRules();
};

async function refreshAll() {
  try {
    await Promise.all([refreshStats(), refreshLogs(), refreshBlocked(), refreshRules()]);
    statusEl.textContent = "connected";
    statusEl.className = "status ok";
  } catch (e) {
    statusEl.textContent = "disconnected — is the backend running on :8000?";
    statusEl.className = "status err";
  }
}

document.getElementById("btn-simulate").addEventListener("click", async () => {
  await api("/api/traffic/simulate", { method: "POST" });
  refreshAll();
});

document.getElementById("btn-simulate-batch").addEventListener("click", async () => {
  await api("/api/traffic/simulate_batch?count=15", { method: "POST" });
  refreshAll();
});

document.getElementById("rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const rule_type = document.getElementById("rule-type").value;
  const value = document.getElementById("rule-value").value.trim();
  const description = document.getElementById("rule-desc").value.trim();
  if (!value) return;
  await api("/api/rules", {
    method: "POST",
    body: JSON.stringify({ rule_type, value, description }),
  });
  document.getElementById("rule-value").value = "";
  document.getElementById("rule-desc").value = "";
  refreshRules();
});

let intervalId;
function setupAutoRefresh() {
  const checkbox = document.getElementById("auto-refresh");
  function apply() {
    if (intervalId) clearInterval(intervalId);
    if (checkbox.checked) intervalId = setInterval(refreshAll, 3000);
  }
  checkbox.addEventListener("change", apply);
  apply();
}

initChart();
refreshAll();
setupAutoRefresh();
