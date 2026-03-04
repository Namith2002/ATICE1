// ============================================================================
// ATICE Advanced Dashboard - Main Application Logic v2.1
// ============================================================================

let authToken = null;
let currentView = "overview";
let charts = {};
let allIOCs = [];
let activityLogs = [];

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
  initializeApp();
});

async function initializeApp() {
  restoreAuthToken();
  if (!authToken) {
    showLoginModal();
  } else {
    hideLoginModal();
    setupEventListeners();
    try {
      loadDashboard();
    } catch (error) {
      console.error("Dashboard load failed:", error);
      // If loading dashboard fails due to auth, show login again
      if (error.message.includes("authenticated") || error.message.includes("Session expired")) {
        authToken = null;
        localStorage.removeItem("aticeToken");
        showLoginModal();
      }
    }
  }
}

// ============================================================================
// Authentication
// ============================================================================

async function login(username, password) {
  try {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
      throw new Error("Invalid credentials");
    }

    const data = await response.json();
    authToken = data.access_token;
    localStorage.setItem("aticeToken", authToken);
    hideLoginModal();
    setupEventListeners();
    loadDashboard();
  } catch (error) {
    showResultBox("error", `Login failed: ${error.message}`);
  }
}

function logout() {
  authToken = null;
  localStorage.removeItem("aticeToken");
  showLoginModal();
}

function restoreAuthToken() {
  authToken = localStorage.getItem("aticeToken");
}

function showLoginModal() {
  document.getElementById("loginModal").classList.add("active");
  document.getElementById("loginForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;
    login(username, password);
  });
}

function hideLoginModal() {
  document.getElementById("loginModal").classList.remove("active");
}

// ============================================================================
// Event Listeners Setup
// ============================================================================

function setupEventListeners() {
  // Navigation
  document.querySelectorAll(".menu-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      switchView(e.target.dataset.view);
    });
  });

  // Dark Mode
  document.getElementById("darkModeToggle").addEventListener("click", toggleDarkMode);

  // Logout
  document.getElementById("logoutBtn").addEventListener("click", logout);

  // Sidebar Actions
  document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
  document.getElementById("exportBtn").addEventListener("click", exportIOCs);

  // Analysis View
  document.getElementById("runAnalysisBtn").addEventListener("click", runAnalysis);

  // Correlations View
  document.getElementById("loadCorrelationsBtn").addEventListener("click", loadCorrelations);
  document.getElementById("correlationThreshold").addEventListener("input", (e) => {
    document.getElementById("thresholdValue").textContent = e.target.value;
  });

  // Reports View
  if (document.getElementById("generateReportBtn")) {
    document.getElementById("generateReportBtn").addEventListener("click", generateReport);
    document.getElementById("exportReportBtn").addEventListener("click", exportReport);
  }

  // Settings View
  if (document.getElementById("saveSettingsBtn")) {
    document.getElementById("saveSettingsBtn").addEventListener("click", saveSettings);
    document.getElementById("backupBtn").addEventListener("click", backupData);
    document.getElementById("restoreBtn").addEventListener("click", restoreData);
    document.getElementById("purgeBtn").addEventListener("click", purgeOldData);
  }

  // Users View
  if (document.getElementById("addUserBtn")) {
    document.getElementById("addUserBtn").addEventListener("click", addNewUser);
  }

  // Logs View
  if (document.getElementById("clearLogsBtn")) {
    document.getElementById("logSearch").addEventListener("input", filterLogs);
    document.getElementById("logLevel").addEventListener("change", filterLogs);
    document.getElementById("clearLogsBtn").addEventListener("click", clearActivityLogs);
  }

  // Ingest Form
  document.getElementById("ingestForm").addEventListener("submit", submitIngestForm);

  // Search & Filters
  document.getElementById("searchInput").addEventListener("input", filterIOCs);
  document.getElementById("typeFilter").addEventListener("change", filterIOCs);
  document.getElementById("threatFilter").addEventListener("change", filterIOCs);

  // Modal Close
  document.querySelectorAll(".close").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.target.closest(".modal").classList.remove("active");
    });
  });
}

// ============================================================================
// View Navigation
// ============================================================================

function switchView(viewName) {
  // Hide all views
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll(".menu-item").forEach(m => m.classList.remove("active"));

  // Show selected view
  document.getElementById(`${viewName}-view`).classList.add("active");
  document.querySelector(`[data-view="${viewName}"]`).classList.add("active");
  currentView = viewName;

  // Load data for view
  switch (viewName) {
    case "overview":
      loadDashboard();
      break;
    case "analysis":
      break;
    case "correlations":
      break;
    case "iocs":
      loadIOCsList();
      break;
    case "ingest":
      break;
    case "reports":
      loadReports();
      break;
    case "users":
      loadUsers();
      break;
    case "logs":
      loadActivityLogs();
      break;
    case "settings":
      loadSettings();
      break;
  }
}

// ============================================================================
// Dashboard Loading
// ============================================================================

async function loadDashboard() {
  try {
    // Load threat analysis
    const analysisRes = await apiCall("POST", "/analyze");
    renderThreatAnalysis(analysisRes);
    updateSidebarStats(analysisRes);

    // Load IOCs for overview
    const iocsRes = await apiCall("GET", "/iocs?limit=100");
    renderOverviewCharts(iocsRes, analysisRes);
  } catch (error) {
    console.error("Dashboard load failed:", error);
  }
}

function renderThreatAnalysis(data) {
  const html = `
    <div class="stat-card critical" style="display: flex; justify-content: space-between; margin: 0.5rem 0;">
      <span>🔴 Critical</span>
      <strong>${data.critical_threats}</strong>
    </div>
    <div class="stat-card high" style="display: flex; justify-content: space-between; margin: 0.5rem 0;">
      <span>🟠 High</span>
      <strong>${data.high_threats}</strong>
    </div>
    <div class="stat-card" style="display: flex; justify-content: space-between; margin: 0.5rem 0; border-left: 4px solid #ff9800;">
      <span>🟡 Medium</span>
      <strong>${data.medium_threats}</strong>
    </div>
    <div class="stat-card" style="display: flex; justify-content: space-between; margin: 0.5rem 0; border-left: 4px solid #5cb85c;">
      <span>🟢 Low</span>
      <strong>${data.low_threats}</strong>
    </div>
    <div style="margin-top: 1rem; padding: 1rem; background: var(--color-bg); border-radius: var(--radius);">
      <div>Avg Score: <strong>${data.average_score.toFixed(1)}</strong>/100</div>
    </div>
  `;
  document.getElementById("latestAnalysis").innerHTML = html;

  // Render sources
  const sourceHtml = Object.entries(data.top_sources)
    .slice(0, 5)
    .map(([source, count]) => `
      <div class="source-item">
        <span class="source-name">${source}</span>
        <span class="source-count">${count}</span>
      </div>
    `)
    .join("");
  document.getElementById("sourcesList").innerHTML = sourceHtml || "<p>No sources</p>";
}

function updateSidebarStats(data) {
  document.getElementById("statTotalIOCs").textContent = data.total_iocs;
  document.getElementById("statCritical").textContent = data.critical_threats;
  document.getElementById("statHigh").textContent = data.high_threats;
  document.getElementById("statAvgScore").textContent = data.average_score.toFixed(1);
}

function renderOverviewCharts(iocs, analysis) {
  // Prepare chart data
  const threatCounts = {
    "Critical": analysis.critical_threats,
    "High": analysis.high_threats,
    "Medium": analysis.medium_threats,
    "Low": analysis.low_threats
  };

  const typeCounts = {};
  iocs.forEach(ioc => {
    typeCounts[ioc.type] = (typeCounts[ioc.type] || 0) + 1;
  });

  // Threat chart
  const threatCtx = document.getElementById("threatChart");
  if (charts.threat) charts.threat.destroy();
  charts.threat = new Chart(threatCtx, {
    type: "doughnut",
    data: {
      labels: Object.keys(threatCounts),
      datasets: [{
        data: Object.values(threatCounts),
        backgroundColor: [
          "rgba(139, 0, 0, 0.8)",
          "rgba(217, 83, 79, 0.8)",
          "rgba(255, 152, 0, 0.8)",
          "rgba(92, 184, 92, 0.8)"
        ],
        borderColor: ["#8b0000", "#d9534f", "#ff9800", "#5cb85c"],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: "bottom"
        }
      }
    }
  });

  // Types chart
  const typesCtx = document.getElementById("typesChart");
  if (charts.types) charts.types.destroy();
  charts.types = new Chart(typesCtx, {
    type: "bar",
    data: {
      labels: Object.keys(typeCounts),
      datasets: [{
        label: "Count",
        data: Object.values(typeCounts),
        backgroundColor: "rgba(0, 102, 255, 0.6)",
        borderColor: "rgba(0, 102, 255, 1)",
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

// ============================================================================
// Analysis View
// ============================================================================

async function runAnalysis() {
  try {
    const result = await apiCall("POST", "/analyze");
    const html = `
      <div class="analysis-summary">
        <div class="summary-stat">
          <label>Total IOCs</label>
          <value>${result.total_iocs}</value>
        </div>
        <div class="summary-stat">
          <label>Critical Threats</label>
          <value style="color: #8b0000;">${result.critical_threats}</value>
        </div>
        <div class="summary-stat">
          <label>High Threats</label>
          <value style="color: #d9534f;">${result.high_threats}</value>
        </div>
        <div class="summary-stat">
          <label>Medium Threats</label>
          <value style="color: #ff9800;">${result.medium_threats}</value>
        </div>
        <div class="summary-stat">
          <label>Low Threats</label>
          <value style="color: #5cb85c;">${result.low_threats}</value>
        </div>
        <div class="summary-stat">
          <label>Average Score</label>
          <value>${result.average_score.toFixed(2)}</value>
        </div>
      </div>
    `;
    document.getElementById("analysisResults").innerHTML = html;
  } catch (error) {
    showResultBox("error", `Analysis failed: ${error.message}`);
  }
}

// ============================================================================
// Correlations View
// ============================================================================

async function loadCorrelations() {
  try {
    const threshold = document.getElementById("correlationThreshold").value;
    const result = await apiCall("GET", `/correlations?threshold=${threshold}`);

    const statsHtml = `
      <div class="stat-item">
        <div class="stat-item-label">Total Nodes</div>
        <div class="stat-item-value">${result.summary.total_nodes}</div>
      </div>
      <div class="stat-item">
        <div class="stat-item-label">Correlations</div>
        <div class="stat-item-value">${result.summary.total_edges}</div>
      </div>
      <div class="stat-item">
        <div class="stat-item-label">Avg Score</div>
        <div class="stat-item-value">${result.summary.avg_score.toFixed(2)}</div>
      </div>
      <div class="stat-item">
        <div class="stat-item-label">Clusters</div>
        <div class="stat-item-value">${result.summary.clusters}</div>
      </div>
    `;
    document.getElementById("correlationStats").innerHTML = statsHtml;

    // Show success popup
    alert("✅ Correlations successfully loaded!");
    
    // TODO: Render correlation graph (would need D3.js or similar)
    console.log("Correlations loaded:", result);
  } catch (error) {
    showResultBox("error", `Correlations failed: ${error.message}`);
  }
}

// ============================================================================
// IOCs List View
// ============================================================================

async function loadIOCsList() {
  try {
    const iocs = await apiCall("GET", "/iocs?limit=500");
    renderIOCsTable(iocs);
  } catch (error) {
    showResultBox("error", `Failed to load IOCs: ${error.message}`);
  }
}

function renderIOCsTable(iocs) {
  if (!iocs || iocs.length === 0) {
    document.getElementById("iocsList").innerHTML = "<p>No IOCs found</p>";
    return;
  }

  const html = `
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>Value</th>
          <th>Score</th>
          <th>Threat Level</th>
          <th>Source</th>
          <th>Detections</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${iocs.map(ioc => `
          <tr>
            <td><strong>${ioc.type.toUpperCase()}</strong></td>
            <td>${ioc.value}</td>
            <td>${ioc.score.toFixed(1)}</td>
            <td><span class="badge badge-${getThreatLevelClass(ioc.score)}">
              ${getThreatLevel(ioc.score)}
            </span></td>
            <td>${ioc.source}</td>
            <td>${ioc.detections || 0}</td>
            <td>
              <button onclick="showIOCDetails('${ioc.id}')" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.875rem;">
                View
              </button>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
  document.getElementById("iocsList").innerHTML = html;
}

function filterIOCs() {
  const search = document.getElementById("searchInput").value.toLowerCase();
  const typeFilter = document.getElementById("typeFilter").value;
  const threatFilter = document.getElementById("threatFilter").value;

  const rows = document.querySelectorAll("table tbody tr");
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const type = row.cells[0].textContent;
    const threatLevel = row.cells[3].textContent;

    const matchSearch = !search || text.includes(search);
    const matchType = !typeFilter || type.includes(typeFilter.toUpperCase());
    const matchThreat = !threatFilter || threatLevel.includes(threatFilter);

    row.style.display = matchSearch && matchType && matchThreat ? "" : "none";
  });
}

async function showIOCDetails(iocId) {
  try {
    const ioc = await apiCall("GET", `/iocs/${iocId}`);
    const modal = document.getElementById("detailsModal");
    const content = document.getElementById("detailsContent");

    content.innerHTML = `
      <div class="analysis-container">
        <div class="summary-stat">
          <label>Type</label>
          <value>${ioc.type}</value>
        </div>
        <div class="summary-stat">
          <label>Value</label>
          <value>${ioc.value}</value>
        </div>
        <div class="summary-stat">
          <label>Score</label>
          <value>${ioc.score}</value>
        </div>
        <div class="summary-stat">
          <label>Threat Level</label>
          <value>${getThreatLevel(ioc.score)}</value>
        </div>
        <div class="summary-stat">
          <label>Source</label>
          <value>${ioc.source}</value>
        </div>
        <div class="summary-stat">
          <label>Confidence</label>
          <value>${(ioc.confidence * 100).toFixed(0)}%</value>
        </div>
        <div class="summary-stat">
          <label>First Seen</label>
          <value>${new Date(ioc.first_seen).toLocaleString()}</value>
        </div>
        <div class="summary-stat">
          <label>Last Seen</label>
          <value>${new Date(ioc.last_seen).toLocaleString()}</value>
        </div>
        <div class="summary-stat">
          <label>Description</label>
          <value>${ioc.description || "N/A"}</value>
        </div>
      </div>
    `;
    modal.classList.add("active");
  } catch (error) {
    alert(`Failed to load IOC details: ${error.message}`);
  }
}

// ============================================================================
// Ingest Form
// ============================================================================

async function submitIngestForm(e) {
  e.preventDefault();

  const ioc = {
    type: document.getElementById("iocType").value,
    value: document.getElementById("iocValue").value,
    source: document.getElementById("iocSource").value || "manual",
    description: document.getElementById("iocDescription").value,
    confidence: parseFloat(document.getElementById("iocConfidence").value),
    metadata: {}
  };

  try {
    const result = await apiCall("POST", "/iocs", ioc);
    showResultBox("success", `IOC ingested successfully! Score: ${result.score}`);
    document.getElementById("ingestForm").reset();
    loadDashboard();
  } catch (error) {
    showResultBox("error", `Failed to ingest IOC: ${error.message}`);
  }
}

// ============================================================================
// Export
// ============================================================================

async function exportIOCs() {
  try {
    const result = await apiCall("GET", "/export?format=json");
    const iocsContainer = document.createElement("div");
    iocsContainer.style.padding = "20px";
    iocsContainer.innerHTML = "<h2>IOCs Export Report</h2>";
    
    if (result.data && Array.isArray(result.data)) {
      iocsContainer.innerHTML += `<p><strong>Total IOCs:</strong> ${result.data.length}</p>`;
      iocsContainer.innerHTML += "<table style='width:100%; border-collapse: collapse; margin-top: 15px;'><thead style='background-color: #f0f0f0;'><tr><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Type</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Value</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Threat Level</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Score</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Confidence</th></tr></thead><tbody>";
      result.data.slice(0, 100).forEach(ioc => {
        const threatLevel = ioc.threat_level || 'Unknown';
        iocsContainer.innerHTML += `<tr><td style='border: 1px solid #ddd; padding: 8px;'>${ioc.type}</td><td style='border: 1px solid #ddd; padding: 8px;'>${ioc.value}</td><td style='border: 1px solid #ddd; padding: 8px;'>${threatLevel}</td><td style='border: 1px solid #ddd; padding: 8px;'>${(ioc.score || 0).toFixed(2)}</td><td style='border: 1px solid #ddd; padding: 8px;'>${(ioc.confidence || 0).toFixed(2)}</td></tr>`;
      });
      iocsContainer.innerHTML += "</tbody></table>";
    }
    
    const opt = {
      margin: 10,
      filename: `iocs-export-${new Date().toISOString().split("T")[0]}.pdf`,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2 },
      jsPDF: { orientation: "landscape", unit: "mm", format: "a4" }
    };
    
    html2pdf().set(opt).from(iocsContainer).save();
    showResultBox("success", "IOCs exported to PDF successfully!");
  } catch (error) {
    showResultBox("error", `Export failed: ${error.message}`);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

function getThreatLevel(score) {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 50) return "MEDIUM";
  if (score >= 30) return "LOW";
  return "INFO";
}

function getThreatLevelClass(score) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 50) return "medium";
  return "low";
}

// ============================================================================
// Reports Page Handlers
// ============================================================================

async function generateReport() {
  try {
    const analysisRes = await apiCall("POST", "/analyze");
    const iocsRes = await apiCall("GET", "/iocs?limit=1000");
    
    // Generate daily summary
    const summary = `
      <strong>Date:</strong> ${new Date().toLocaleDateString()}<br>
      <strong>Total IOCs:</strong> ${iocsRes.length}<br>
      <strong>Critical Threats:</strong> ${analysisRes.critical_threats}<br>
      <strong>High Threats:</strong> ${analysisRes.high_threats}<br>
      <strong>Average Score:</strong> ${(iocsRes.reduce((sum, ioc) => sum + ioc.score, 0) / iocsRes.length).toFixed(2)}<br>
      <strong>Most Common Type:</strong> ${getMostCommonType(iocsRes)}<br>
    `;
    
    document.getElementById("dailySummary").innerHTML = summary;
    
    // Generate top threats list
    const topIOCs = iocsRes.sort((a, b) => b.score - a.score).slice(0, 10);
    const threatsHTML = topIOCs.map(ioc => `
      <li>
        <strong>${ioc.value}</strong> (${ioc.type}) - Score: ${ioc.score}
        <span class="threat-badge ${getThreatLevel(ioc.score)}">${getThreatLevel(ioc.score).toUpperCase()}</span>
      </li>
    `).join("");
    document.getElementById("threatsListReport").innerHTML = threatsHTML;
    
    // Generate statistics
    const statsHTML = `
      <div class="stat-item"><strong>Total IOCs:</strong> ${iocsRes.length}</div>
      <div class="stat-item"><strong>Critical:</strong> ${iocsRes.filter(i => i.score >= 90).length}</div>
      <div class="stat-item"><strong>High:</strong> ${iocsRes.filter(i => i.score >= 70 && i.score < 90).length}</div>
      <div class="stat-item"><strong>Medium:</strong> ${iocsRes.filter(i => i.score >= 50 && i.score < 70).length}</div>
    `;
    document.getElementById("statsGrid").innerHTML = statsHTML;
  } catch (error) {
    showResultBox("error", `Report generation failed: ${error.message}`);
  }
}

function getMostCommonType(iocs) {
  const types = {};
  iocs.forEach(ioc => {
    types[ioc.type] = (types[ioc.type] || 0) + 1;
  });
  return Object.keys(types).reduce((a, b) => types[a] > types[b] ? a : b, "unknown");
}

function exportReport() {
  const element = document.querySelector(".reports-container");
  const opt = {
    margin: 10,
    filename: `threat-report-${new Date().toISOString().split('T')[0]}.pdf`,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: { scale: 2 },
    jsPDF: { orientation: 'portrait', unit: 'mm', format: 'a4' }
  };
  
  html2pdf().set(opt).from(element).save();
}

// ============================================================================
// Users Page Handlers
// ============================================================================

function loadUsers() {
  // Users page already populated with static data
  console.log("Users page loaded");
}

function addNewUser() {
  const username = prompt("Enter username:");
  if (!username) return;
  
  const email = prompt("Enter email:");
  if (!email) return;
  
  const role = prompt("Enter role (Admin/Analyst/Viewer):");
  if (!role) return;
  
  showResultBox("success", `User ${username} created successfully`);
  
  // Add to table
  const tbody = document.getElementById("usersTableBody");
  const row = tbody.insertRow();
  row.innerHTML = `
    <td>${username}</td>
    <td>${email}</td>
    <td><span class="badge badge-${role.toLowerCase()}">${role}</span></td>
    <td><span class="badge badge-active">Active</span></td>
    <td>Today</td>
    <td><button class="btn btn-sm">Edit</button></td>
  `;
}

// ============================================================================
// Activity Logs Page Handlers
// ============================================================================

function loadActivityLogs() {
  // Log page initialized with sample data
  // Add a new log entry for page load
  addLogEntry("Page View", "Loaded activity logs page", "info");
}

function addLogEntry(action, details, level = "info") {
  const timestamp = new Date().toLocaleString();
  const username = "admin"; // Current user
  
  activityLogs.unshift({ timestamp, username, action, level, details });
  
  if (!document.getElementById("logsTableBody")) return;
  
  const tbody = document.getElementById("logsTableBody");
  const row = tbody.insertRow(0);
  row.innerHTML = `
    <td>${timestamp}</td>
    <td>${username}</td>
    <td>${action}</td>
    <td><span class="log-level ${level}">${level.toUpperCase()}</span></td>
    <td>${details}</td>
  `;
}

function filterLogs() {
  const searchTerm = document.getElementById("logSearch")?.value || "";
  const levelFilter = document.getElementById("logLevel")?.value || "";
  
  const rows = document.querySelectorAll(".logs-table tbody tr");
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const level = row.querySelector(".log-level")?.textContent.toLowerCase() || "";
    
    const matchesSearch = text.includes(searchTerm.toLowerCase());
    const matchesLevel = !levelFilter || level.includes(levelFilter.toLowerCase());
    
    row.style.display = matchesSearch && matchesLevel ? "" : "none";
  });
}

function clearActivityLogs() {
  if (confirm("Are you sure you want to clear all logs?")) {
    activityLogs = [];
    const tbody = document.getElementById("logsTableBody");
    if (tbody) tbody.innerHTML = "";
    showResultBox("success", "Activity logs cleared");
  }
}

// ============================================================================
// Settings Page Handlers
// ============================================================================

function loadSettings() {
  // Settings page loaded with static form
  console.log("Settings page loaded");
}

function saveSettings() {
  const settings = {
    systemName: document.querySelector(".settings-input")?.value,
    criticalThreshold: 90,
    highThreshold: 70,
    emailNotif: document.getElementById("emailNotif")?.checked
  };
  
  localStorage.setItem("aticeSettings", JSON.stringify(settings));
  showResultBox("success", "Settings saved successfully");
  alert("✅ Settings successfully saved!");
  addLogEntry("Settings Updated", "System settings modified", "info");
}

function backupData() {
  if (!allIOCs.length) {
    showResultBox("warning", "No data to backup");
    return;
  }
  
  const backup = {
    timestamp: new Date().toISOString(),
    iocs: allIOCs,
    count: allIOCs.length
  };
  
  const element = document.createElement("a");
  element.setAttribute("href", "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(backup, null, 2)));
  element.setAttribute("download", `atice-backup-${new Date().toISOString().split('T')[0]}.json`);
  element.click();
  
  showResultBox("success", `Backup created with ${allIOCs.length} IOCs`);
  addLogEntry("Data Backup", `Backed up ${allIOCs.length} IOCs`, "success");
}

function restoreData() {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".json";
  input.onchange = (e) => {
    const file = e.target.files[0];
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const backup = JSON.parse(event.target.result);
        allIOCs = backup.iocs;
        showResultBox("success", `Restored ${backup.count} IOCs`);
        addLogEntry("Data Restore", `Restored ${backup.count} IOCs`, "success");
      } catch (error) {
        showResultBox("error", "Invalid backup file");
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function purgeOldData() {
  const daysOld = prompt("Delete IOCs older than (days):", "30");
  if (!daysOld) return;
  
  const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
  const initialCount = allIOCs.length;
  
  allIOCs = allIOCs.filter(ioc => new Date(ioc.first_seen) > cutoffDate);
  
  const deleted = initialCount - allIOCs.length;
  showResultBox("success", `Purged ${deleted} old IOCs`);
  addLogEntry("Data Purge", `Purged ${deleted} IOCs older than ${daysOld} days`, "info");
}

async function apiCall(method, path, body = null) {
  // Check if user is authenticated
  if (!authToken) {
    throw new Error("Not authenticated. Please log in first.");
  }

  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${authToken}`
    }
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(API_BASE + path, options);

  if (response.status === 401) {
    // Token is invalid/expired, clear it and redirect to login
    authToken = null;
    localStorage.removeItem("aticeToken");
    showLoginModal();
    throw new Error("Session expired. Please log in again.");
  }

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

function showResultBox(type, message) {
  const box = document.getElementById("ingestResult");
  box.className = `result-box ${type}`;
  box.textContent = message;
  setTimeout(() => {
    box.className = "result-box";
  }, 5000);
}

function toggleDarkMode() {
  document.body.classList.toggle("dark-mode");
  localStorage.setItem("darkMode", document.body.classList.contains("dark-mode"));
}

// Load dark mode preference
if (localStorage.getItem("darkMode") === "true") {
  document.body.classList.add("dark-mode");
}
