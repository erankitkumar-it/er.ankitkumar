const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content ?? "";
const scanForm = document.querySelector("#scan-form");
const urlInput = document.querySelector("#url-input");
const scanButton = document.querySelector("#scan-button");
const formMessage = document.querySelector("#form-message");
const resultPanel = document.querySelector("#scan-result");
const historyBody = document.querySelector("#history-body");
const clearButton = document.querySelector("#clear-history");
const historySearch = document.querySelector("#history-search");
const historyFilter = document.querySelector("#history-filter");
const toastRegion = document.querySelector("#toast-region");
let detectionChart;
let historySearchTimer;
let lastScan;

function renderIcons() {
    window.lucide?.createIcons();
}

function setLoading(isLoading) {
    scanButton.disabled = isLoading;
    scanButton.querySelector(".button-label").hidden = isLoading;
    scanButton.querySelector(".button-loading").hidden = !isLoading;
}

function showMessage(message) {
    formMessage.textContent = message;
    formMessage.hidden = !message;
    if (message) showToast("error", message);
}

function showResult(scan) {
    resultPanel.replaceChildren();
    resultPanel.className = `result-panel result-${scan.prediction}`;
    resultPanel.hidden = false;
    lastScan = scan;

    const symbol = document.createElement("span");
    const classification = scan.prediction;
    const iconName = classification === "phishing" ? "shield-alert" : classification === "suspicious" ? "triangle-alert" : "badge-check";
    symbol.className = `result-symbol result-${classification}`;
    const icon = document.createElement("i");
    icon.dataset.lucide = iconName;
    symbol.append(icon);

    const copy = document.createElement("div");
    copy.className = "result-copy";
    const label = document.createElement("p");
    label.className = "result-label";
    label.textContent = `${classification.toUpperCase()} CLASSIFICATION`;
    const url = document.createElement("h3");
    url.textContent = scan.url;
    const note = document.createElement("p");
    note.className = "result-note";
    note.textContent = scan.uncertain
        ? "Model uncertainty: review the indicators before relying on this result."
        : "Model-based assessment only; this does not verify that a site is safe.";
    copy.append(label, url, note);
    resultPanel.append(symbol, copy);

    const scores = document.createElement("div");
    scores.className = "result-scores";
    for (const [className, value, caption] of [
        ["risk-score", `${Number(scan.risk_score).toFixed(1)}%`, "risk score"],
        ["result-confidence", `${(Number(scan.confidence) * 100).toFixed(1)}%`, "model confidence"],
    ]) {
        const score = document.createElement("span");
        score.className = className;
        score.append(document.createTextNode(value));
        const scoreLabel = document.createElement("small");
        scoreLabel.textContent = caption;
        score.append(scoreLabel);
        scores.append(score);
    }
    const copyButton = document.createElement("button");
    copyButton.className = "copy-result";
    copyButton.type = "button";
    copyButton.dataset.copyResult = "";
    copyButton.title = "Copy scan result";
    copyButton.setAttribute("aria-label", "Copy scan result");
    const copyIcon = document.createElement("i");
    copyIcon.dataset.lucide = "copy";
    copyButton.append(copyIcon);
    scores.append(copyButton);
    resultPanel.append(scores);

    const reasons = document.createElement("ul");
    reasons.className = "result-reasons";
    for (const reason of scan.reasons ?? []) {
        const item = document.createElement("li");
        item.textContent = reason;
        reasons.append(item);
    }
    resultPanel.append(reasons);

    const featureDetails = document.createElement("details");
    featureDetails.className = "feature-details";
    const summary = document.createElement("summary");
    summary.textContent = "URL feature analysis";
    const featureList = document.createElement("div");
    featureList.className = "feature-list";
    const featureValues = [
        `URL length: ${scan.features?.url_length ?? "N/A"}`,
        `Subdomains: ${scan.features?.subdomain_count ?? "N/A"}`,
        `IP host: ${scan.features?.uses_ip_address ? "Yes" : "No"}`,
        `Shortener: ${scan.features?.uses_url_shortener ? "Yes" : "No"}`,
        `Query present: ${scan.features?.has_query_parameters ? "Yes" : "No"}`,
        `Keywords: ${scan.features?.suspicious_keywords?.join(", ") || "None"}`,
    ];
    for (const value of featureValues) {
        const item = document.createElement("span");
        item.textContent = value;
        featureList.append(item);
    }
    featureDetails.append(summary, featureList);
    resultPanel.append(featureDetails);
    renderIcons();
}

function updateMetrics(stats) {
    document.querySelector("#metric-total").textContent = stats.total_scans;
    document.querySelector("#metric-safe").textContent = stats.safe_detected;
    document.querySelector("#metric-suspicious").textContent = stats.suspicious_detected;
    document.querySelector("#metric-phishing").textContent = stats.phishing_detected;
    document.querySelector("#metric-rate").childNodes[0].nodeValue = `${stats.threat_rate}`;
    document.querySelector("#chart-total").textContent = stats.total_scans;
    document.querySelector("#legend-safe").textContent = stats.safe_detected;
    document.querySelector("#legend-suspicious").textContent = stats.suspicious_detected;
    document.querySelector("#legend-phishing").textContent = stats.phishing_detected;
    clearButton.disabled = stats.total_scans === 0;

    if (detectionChart) {
        detectionChart.data.datasets[0].data = [stats.safe_detected, stats.suspicious_detected, stats.phishing_detected];
        detectionChart.update();
    } else if (window.Chart) {
        const context = document.querySelector("#detection-chart");
        detectionChart = new window.Chart(context, {
            type: "doughnut",
            data: {
                labels: ["Safe", "Suspicious", "Phishing"],
                datasets: [{
                    data: [stats.safe_detected, stats.suspicious_detected, stats.phishing_detected],
                    backgroundColor: ["#79dfbb", "#ffbd67", "#ff7785"],
                    borderColor: "#122338",
                    borderWidth: 3,
                    hoverOffset: 4,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "76%",
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: "#101f30", borderColor: "rgba(149,176,204,.2)", borderWidth: 1, padding: 10 },
                },
            },
        });
    }
}

function formatTime(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function renderHistory(scans) {
    historyBody.replaceChildren();
    if (!scans.length) {
        const row = document.createElement("tr");
        row.className = "empty-row";
        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.textContent = "No scans recorded yet.";
        row.append(cell);
        historyBody.append(row);
    } else {
        for (const scan of scans.slice(0, 50)) {
            const row = document.createElement("tr");
            const urlCell = document.createElement("td");
            urlCell.className = "url-cell";
            urlCell.textContent = scan.url;

            const verdictCell = document.createElement("td");
            const verdict = document.createElement("span");
            verdict.className = `verdict verdict-${scan.prediction}`;
            const dot = document.createElement("span");
            verdict.append(dot, document.createTextNode(scan.prediction[0].toUpperCase() + scan.prediction.slice(1)));
            verdictCell.append(verdict);

            const scoreCell = document.createElement("td");
            scoreCell.className = "score-cell";
            scoreCell.textContent = `${Number(scan.risk_score).toFixed(1)}%`;

            const timeCell = document.createElement("td");
            timeCell.className = "time-cell";
            timeCell.textContent = formatTime(scan.scanned_at);
            const actionCell = document.createElement("td");
            const deleteButton = document.createElement("button");
            deleteButton.className = "row-delete";
            deleteButton.type = "button";
            deleteButton.dataset.deleteScan = scan.id;
            deleteButton.title = "Delete scan record";
            deleteButton.setAttribute("aria-label", "Delete scan record");
            const deleteIcon = document.createElement("i");
            deleteIcon.dataset.lucide = "x";
            deleteButton.append(deleteIcon);
            actionCell.append(deleteButton);
            row.append(urlCell, verdictCell, scoreCell, timeCell, actionCell);
            historyBody.append(row);
        }
    }
    document.querySelector("#history-count").textContent = `${scans.length} record${scans.length === 1 ? "" : "s"} shown`;
    renderIcons();
}

function showToast(type, message) {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.setAttribute("role", type === "error" ? "alert" : "status");
    const icon = document.createElement("i");
    icon.dataset.lucide = type === "error" ? "circle-alert" : "circle-check";
    const text = document.createElement("span");
    text.textContent = message;
    toast.append(icon, text);
    toastRegion.replaceChildren(toast);
    renderIcons();
    window.setTimeout(() => toast.remove(), 3500);
}

async function refreshHistory() {
    const parameters = new URLSearchParams({
        search: historySearch.value.trim(),
        classification: historyFilter.value,
        limit: "50",
    });
    const response = await fetch(`/api/history?${parameters}`, { headers: { Accept: "application/json" } });
    if (!response.ok) return;
    const data = await response.json();
    renderHistory(data.scans, data.total);
    document.querySelector("#history-total").textContent = `${data.total} matching scan${data.total === 1 ? "" : "s"}`;
}

async function refreshDashboard() {
    const response = await fetch("/api/stats", { headers: { Accept: "application/json" } });
    if (!response.ok) return;
    const data = await response.json();
    updateMetrics(data.stats);
    await refreshHistory();
}

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    showMessage("");
    resultPanel.hidden = true;
    setLoading(true);
    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
            body: JSON.stringify({ url: urlInput.value }),
        });
        const data = await response.json();
        if (!response.ok) {
            showMessage(data.error ?? "The scan could not be completed.");
            return;
        }
        showResult(data.scan);
        updateMetrics(data.stats);
        await refreshDashboard();
        showToast(data.scan.uncertain ? "warning" : "success", `${data.scan.prediction[0].toUpperCase() + data.scan.prediction.slice(1)} classification recorded.`);
    } catch {
        showMessage("Unable to reach the scanner. Check that the application is running and try again.");
    } finally {
        setLoading(false);
    }
});

resultPanel.addEventListener("click", async (event) => {
    const copyButton = event.target.closest("[data-copy-result]");
    if (!copyButton || !lastScan) return;
    const resultText = [
        `${lastScan.prediction.toUpperCase()} classification`,
        `URL: ${lastScan.url}`,
        `Risk score: ${Number(lastScan.risk_score).toFixed(1)}%`,
        `Model confidence: ${(Number(lastScan.confidence) * 100).toFixed(1)}%`,
        `Reasons: ${(lastScan.reasons ?? []).join("; ")}`,
    ].join("\n");
    try {
        await navigator.clipboard.writeText(resultText);
        showToast("success", "Scan result copied.");
    } catch {
        showToast("error", "Clipboard access is unavailable in this browser.");
    }
});

historySearch.addEventListener("input", () => {
    window.clearTimeout(historySearchTimer);
    historySearchTimer = window.setTimeout(() => refreshHistory().catch(() => {}), 180);
});
historyFilter.addEventListener("change", () => refreshHistory().catch(() => {}));

historyBody.addEventListener("click", async (event) => {
    const deleteButton = event.target.closest("[data-delete-scan]");
    if (!deleteButton) return;
    if (!window.confirm("Delete this scan record?")) return;
    deleteButton.disabled = true;
    try {
        const response = await fetch(`/api/history/${deleteButton.dataset.deleteScan}`, {
            method: "DELETE",
            headers: { "X-CSRF-Token": csrfToken },
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error ?? "Could not delete the scan record.");
        updateMetrics(data.stats);
        await refreshHistory();
        showToast("success", "Scan record deleted.");
    } catch (error) {
        deleteButton.disabled = false;
        showToast("error", error.message);
    }
});

clearButton.addEventListener("click", async () => {
    if (!window.confirm("Clear all saved scan history? This cannot be undone.")) return;
    clearButton.disabled = true;
    try {
        const response = await fetch("/api/history/clear", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
            body: "{}",
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error ?? "Could not clear scan history.");
        updateMetrics(data.stats);
        historySearch.value = "";
        historyFilter.value = "all";
        renderHistory(data.recent_scans);
        document.querySelector("#history-total").textContent = "0 matching scans";
        resultPanel.hidden = true;
        showMessage("");
        showToast("success", "Scan history cleared.");
    } catch (error) {
        showMessage(error.message);
        clearButton.disabled = false;
    }
});

document.querySelector("#current-date").textContent = new Date().toLocaleDateString([], {
    weekday: "short", year: "numeric", month: "short", day: "numeric",
});
renderIcons();
refreshDashboard().catch(() => {});