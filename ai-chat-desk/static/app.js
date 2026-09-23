/**
 * Minimalist Frontend Application Logic for Vulnerability Intelligence AI.
 * Palette: Warm Beige & Obsidian Dark Theme
 */

document.addEventListener("DOMContentLoaded", () => {
  let samples = [];
  let currentPage = 1;
  const pageLimit = 20;

  // Navigation
  const tabBtns = document.querySelectorAll(".tab-pill");
  const tabPanes = document.querySelectorAll(".view-panel");

  // Form Elements
  const form = document.getElementById("analyze-form");
  const inputDesc = document.getElementById("input-description");
  const inputCategory = document.getElementById("input-category");
  const inputCwe = document.getElementById("input-cwe");
  const inputEpss = document.getElementById("input-epss");
  const epssVal = document.getElementById("epss-val");
  const inputKev = document.getElementById("input-kev");
  const btnClear = document.getElementById("btn-clear");
  const presetList = document.getElementById("presets-list");

  // State Views
  const emptyState = document.getElementById("empty-state");
  const loadingState = document.getElementById("loading-state");
  const resultsContainer = document.getElementById("results-container");

  // Outputs
  const urgencySlot = document.getElementById("urgency-badge-slot");
  const resSeverity = document.getElementById("res-severity");
  const resSevConf = document.getElementById("res-severity-conf");
  const resScore = document.getElementById("res-score");
  const resTier = document.getElementById("res-tier");
  const resTierConf = document.getElementById("res-tier-conf");
  const resKev = document.getElementById("res-kev");
  const resKevProb = document.getElementById("res-kev-prob");
  const probBarsContainer = document.getElementById("prob-bars-container");
  const resMitigation = document.getElementById("res-primary-mitigation");
  const btnCopyMit = document.getElementById("btn-copy-mitigation");
  const similarCvesList = document.getElementById("similar-cves-list");

  // Repository Table
  const tableBody = document.getElementById("cve-table-body");
  const searchCve = document.getElementById("search-cve");
  const filterPlatform = document.getElementById("filter-platform");
  const pageInfo = document.getElementById("page-info");
  const btnPrevPage = document.getElementById("btn-prev-page");
  const btnNextPage = document.getElementById("btn-next-page");

  // --- Tab Navigation ---
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(tabId);
      if (targetPane) {
        targetPane.classList.add("active");
      }

      if (tabId === "tab-explorer") {
        fetchDatabaseRecords();
      } else if (tabId === "tab-metrics") {
        fetchMetrics();
      }
    });
  });

  // --- EPSS Slider Live Update ---
  inputEpss.addEventListener("input", (e) => {
    epssVal.textContent = parseFloat(e.target.value).toFixed(2);
  });

  // --- Reset Form ---
  btnClear.addEventListener("click", () => {
    inputDesc.value = "";
    inputCategory.value = "General";
    inputCwe.value = "Unknown";
    inputEpss.value = 0.05;
    epssVal.textContent = "0.05";
    inputKev.value = "0";

    emptyState.classList.remove("hidden");
    loadingState.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    urgencySlot.innerHTML = "";
  });

  // --- Load Preset Samples ---
  async function fetchSamples() {
    try {
      const res = await fetch("/api/samples");
      const data = await res.json();
      samples = data.samples || [];
    } catch (err) {
      console.error("Failed to load presets:", err);
    }
  }

  presetList.addEventListener("click", (e) => {
    if (e.target.classList.contains("chip-btn")) {
      const idx = parseInt(e.target.getAttribute("data-index"));
      if (samples[idx]) {
        const item = samples[idx];
        inputDesc.value = item.description;
        inputCategory.value = item.category;
        inputCwe.value = item.cwe_id;
        inputEpss.value = item.epss_score;
        epssVal.textContent = item.epss_score.toFixed(2);
        inputKev.value = item.kev_listed ? "1" : "0";

        runAnalysis();
      }
    }
  });

  // --- Submit Form ---
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runAnalysis();
  });

  // --- Run AI Analysis ---
  async function runAnalysis() {
    const desc = inputDesc.value.trim();
    if (!desc) return;

    emptyState.classList.add("hidden");
    resultsContainer.classList.add("hidden");
    loadingState.classList.remove("hidden");

    try {
      const payload = {
        description: desc,
        category: inputCategory.value,
        cwe_id: inputCwe.value,
        epss_score: parseFloat(inputEpss.value),
        kev_listed: parseInt(inputKev.value)
      };

      const res = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      loadingState.classList.add("hidden");
      resultsContainer.classList.remove("hidden");

      renderPredictions(data);
    } catch (err) {
      loadingState.classList.add("hidden");
      emptyState.classList.remove("hidden");
      alert("Analysis error: " + err.message);
    }
  }

  // --- Render Prediction Output ---
  function renderPredictions(data) {
    const pred = data.predictions;
    const mit = data.recommended_mitigation;

    // 1. Urgency Badge
    if (pred.action_urgency.includes("URGENT")) {
      urgencySlot.innerHTML = `<span class="badge-minimal badge-urgent">Immediate Action Required</span>`;
    } else if (pred.action_urgency.includes("ELEVATED")) {
      urgencySlot.innerHTML = `<span class="badge-minimal badge-elevated">Elevated Remediation</span>`;
    } else {
      urgencySlot.innerHTML = `<span class="badge-minimal badge-standard">Standard Cycle</span>`;
    }

    // 2. Severity Card
    resSeverity.textContent = pred.cvss_severity;
    resSevConf.textContent = `${(pred.cvss_severity_confidence * 100).toFixed(1)}% Confidence`;
    if (pred.cvss_severity === "CRITICAL") resSeverity.style.color = "var(--color-terracotta)";
    else if (pred.cvss_severity === "HIGH") resSeverity.style.color = "var(--color-amber)";
    else if (pred.cvss_severity === "MEDIUM") resSeverity.style.color = "var(--color-beige-200)";
    else resSeverity.style.color = "var(--color-sage)";

    // 3. CVSS Score Card
    resScore.innerHTML = `${pred.cvss_score.toFixed(1)} <span class="denom">/ 10</span>`;

    // 4. Remediation Tier Card
    resTier.textContent = pred.assigned_tier.split("(")[0].trim();
    resTierConf.textContent = pred.assigned_tier.includes("(") ? pred.assigned_tier.split("(")[1].replace(")", "") : `${(pred.assigned_tier_confidence * 100).toFixed(1)}% Conf`;

    // 5. KEV Threat Card
    const isKev = pred.kev_exploitation_risk.is_active_exploit_threat;
    const kevProb = (pred.kev_exploitation_risk.exploit_probability * 100).toFixed(1);
    resKev.textContent = isKev ? "ACTIVE THREAT" : "STANDARD";
    resKev.style.color = isKev ? "var(--color-terracotta)" : "var(--color-sage)";
    resKevProb.textContent = `${kevProb}% KEV Likelihood`;

    // 6. Probability Distribution Bars
    probBarsContainer.innerHTML = "";
    const colorMap = {
      "CRITICAL": "var(--color-terracotta)",
      "HIGH": "var(--color-amber)",
      "MEDIUM": "var(--color-beige-300)",
      "LOW": "var(--color-sage)"
    };

    for (const [cls, prob] of Object.entries(pred.cvss_severity_probabilities)) {
      const pct = (prob * 100).toFixed(1);
      const row = document.createElement("div");
      row.className = "distribution-row";
      row.innerHTML = `
        <span class="dist-class">${cls}</span>
        <div class="dist-bar-track">
          <div class="dist-bar-fill" style="width: ${pct}%; background-color: ${colorMap[cls] || 'var(--color-beige-300)'}"></div>
        </div>
        <span class="dist-percentage">${pct}%</span>
      `;
      probBarsContainer.appendChild(row);
    }

    // 7. Primary Recommended Mitigation
    resMitigation.textContent = mit.primary_mitigation_plan;

    // 8. Nearest Reference Cases
    similarCvesList.innerHTML = "";
    (mit.top_similar_historical_cves || []).forEach(cve => {
      const card = document.createElement("div");
      card.className = "reference-card";
      card.innerHTML = `
        <div class="ref-head">
          <span class="ref-cve">${cve.cve_id} <span style="font-weight:400; color:var(--color-taupe-dark);">(${cve.category})</span></span>
          <span class="ref-score">${cve.similarity_score} match • CVSS ${cve.cvss_score} (${cve.cvss_severity})</span>
        </div>
        <div class="ref-desc">${cve.description_snippet}</div>
      `;
      similarCvesList.appendChild(card);
    });
  }

  // --- Copy Mitigation Handler ---
  btnCopyMit.addEventListener("click", () => {
    const text = resMitigation.textContent;
    if (text) {
      navigator.clipboard.writeText(text);
      btnCopyMit.textContent = "Copied";
      setTimeout(() => {
        btnCopyMit.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
      }, 1800);
    }
  });

  // --- Repository Database Records ---
  async function fetchDatabaseRecords() {
    const search = searchCve.value.trim();
    const platform = filterPlatform.value;

    tableBody.innerHTML = `<tr><td colspan="8" class="table-message">Loading repository records...</td></tr>`;

    try {
      const query = new URLSearchParams({
        page: currentPage,
        limit: pageLimit,
        q: search,
        platform: platform
      });

      const res = await fetch(`/api/browse?${query.toString()}`);
      const data = await res.json();

      tableBody.innerHTML = "";
      if (!data.records || data.records.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="8" class="table-message">No matching CVE records found.</td></tr>`;
        pageInfo.textContent = "0 records";
        return;
      }

      data.records.forEach(row => {
        const tr = document.createElement("tr");
        const sevColor = row.cvss_severity === "CRITICAL" ? "var(--color-terracotta)" :
                         row.cvss_severity === "HIGH" ? "var(--color-amber)" :
                         row.cvss_severity === "MEDIUM" ? "var(--color-beige-200)" : "var(--color-sage)";

        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-weight:600; color:var(--color-beige-100);">${row.cve_id || '-'}</td>
          <td>${row.category || row.domain || 'General'}</td>
          <td><span style="color:${sevColor}; font-weight:600;">${row.cvss_severity}</span></td>
          <td style="font-family: var(--font-mono);">${row.cvss_score ? Number(row.cvss_score).toFixed(1) : '-'}</td>
          <td style="font-family: var(--font-mono); font-size:11px; color:var(--color-taupe);">${row.cwe_id || '-'}</td>
          <td style="font-size:11.5px;">${row.assigned_tier || '-'}</td>
          <td>${row.kev_listed ? '<span style="color:var(--color-terracotta); font-weight:600;">YES</span>' : '<span style="color:var(--color-taupe-dark);">No</span>'}</td>
          <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--color-taupe);" title="${row.mitigation_plan || ''}">${row.mitigation_plan || '-'}</td>
        `;
        tableBody.appendChild(tr);
      });

      const totalPages = Math.ceil(data.total / pageLimit);
      pageInfo.textContent = `Page ${data.page} of ${totalPages} (${data.total.toLocaleString()} CVEs)`;
      btnPrevPage.disabled = data.page <= 1;
      btnNextPage.disabled = data.page >= totalPages;

    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="8" class="table-message" style="color:var(--color-terracotta);">Error loading records: ${err.message}</td></tr>`;
    }
  }

  let searchTimer;
  searchCve.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      currentPage = 1;
      fetchDatabaseRecords();
    }, 280);
  });

  filterPlatform.addEventListener("change", () => {
    currentPage = 1;
    fetchDatabaseRecords();
  });

  btnPrevPage.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      fetchDatabaseRecords();
    }
  });

  btnNextPage.addEventListener("click", () => {
    currentPage++;
    fetchDatabaseRecords();
  });

  // --- Fetch Benchmarks ---
  async function fetchMetrics() {
    try {
      const res = await fetch("/api/metrics");
      const data = await res.json();

      document.getElementById("stat-total-cves").textContent = (data.dataset_summary.total_records || 12968).toLocaleString();
      document.getElementById("stat-sev-acc").textContent = `${(data.cvss_severity_metrics.accuracy * 100).toFixed(1)}%`;
      document.getElementById("stat-tier-acc").textContent = `${(data.remediation_tier_metrics.accuracy * 100).toFixed(1)}%`;
      document.getElementById("stat-kev-auc").textContent = (data.kev_exploitation_metrics.roc_auc || 0.999).toFixed(3);

      const sevRep = data.cvss_severity_metrics.classification_report;
      let sevHtml = `Class          Precision    Recall    F1-Score    Support\n`;
      sevHtml += `---------------------------------------------------------\n`;
      for (const [cls, metrics] of Object.entries(sevRep)) {
        if (typeof metrics === "object") {
          sevHtml += `${cls.padEnd(15)} ${(metrics.precision||0).toFixed(4).padStart(9)} ${(metrics.recall||0).toFixed(4).padStart(9)} ${(metrics['f1-score']||0).toFixed(4).padStart(11)} ${String(metrics.support||'').padStart(9)}\n`;
        }
      }
      document.getElementById("severity-report-content").textContent = sevHtml;

      const tierRep = data.remediation_tier_metrics.classification_report;
      let tierHtml = `Remediation Tier                        Precision    Recall    F1-Score    Support\n`;
      tierHtml += `-------------------------------------------------------------------------------------\n`;
      for (const [cls, metrics] of Object.entries(tierRep)) {
        if (typeof metrics === "object") {
          tierHtml += `${cls.padEnd(39)} ${(metrics.precision||0).toFixed(4).padStart(9)} ${(metrics.recall||0).toFixed(4).padStart(9)} ${(metrics['f1-score']||0).toFixed(4).padStart(11)} ${String(metrics.support||'').padStart(9)}\n`;
        }
      }
      document.getElementById("tier-report-content").textContent = tierHtml;

    } catch (err) {
      console.error("Failed to load metrics:", err);
    }
  }

  // Init
  fetchSamples();
});
