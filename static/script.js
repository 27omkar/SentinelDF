const statusText = document.getElementById("statusText");
const statusDescription = document.getElementById("statusDescription");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");

async function requestJSON(url, options = {}) {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
    return response.json();
}
function setStage(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}
function showTableMessage(table, columns, message) {
    if (!table) return;
    table.replaceChildren();
    const row = table.insertRow();
    const cell = row.insertCell();
    cell.colSpan = columns;
    cell.textContent = message;
    cell.style.padding = "20px";
}
function addCell(row, value) {
    const cell = row.insertCell();
    cell.textContent = value == null ? "" : String(value);
    cell.style.padding = "12px";
    cell.style.borderTop = "1px solid #263149";
    return cell;
}
async function refreshStatus() {
    try {
        const data = await requestJSON("/api/status");
        statusText.textContent = data.monitoring ? "● Monitoring enabled" : "● Monitoring stopped";
        const folders = Array.isArray(data.watched_folders) ? data.watched_folders : [];
        statusDescription.textContent = data.monitoring
            ? `Monitoring ${folders.length || 1} configured folder(s).`
            : "Monitoring is stopped.";
        document.getElementById("events").textContent = data.events ?? 0;
        document.getElementById("alertCount").textContent = data.alerts ?? 0;
        setStage("watcherStage", data.watcher_alive ? "ACTIVE" : "IDLE");
        startBtn.disabled = Boolean(data.monitoring);
        stopBtn.disabled = !data.monitoring;
    } catch (e) {
        statusDescription.textContent = "Backend unavailable. Check the Flask terminal.";
        console.error(e);
    }
}
async function refreshEvents() {
    const table = document.getElementById("eventsTable");
    try {
        const events = await requestJSON("/api/events");
        table.replaceChildren();
        if (!Array.isArray(events) || !events.length) return showTableMessage(table, 3, "No file activity recorded.");
        events.slice().reverse().slice(0, 25).forEach(event => {
            const row = table.insertRow();
            addCell(row, event.time);
            addCell(row, event.type);
            addCell(row, event.path || event.file);
        });
    } catch (e) {
        showTableMessage(table, 3, "Could not load file activity.");
        console.error(e);
    }
}
async function refreshEntropy() {
    try {
        const results = await requestJSON("/api/entropy");
        if (!Array.isArray(results) || !results.length) {
            document.getElementById("entropy").textContent = "Waiting for data";
            document.getElementById("entropyDetails").textContent = "No available file results";
            setStage("entropyStage", "WAITING"); return;
        }
        const r = results[0];
        if (typeof r.entropy !== "number") {
            document.getElementById("entropy").textContent = "Unavailable";
            document.getElementById("entropyDetails").textContent = r.status || "No entropy value returned";
            setStage("entropyStage", "CHECK"); return;
        }
        document.getElementById("entropy").textContent = `${r.entropy.toFixed(3)} bits/byte`;
        document.getElementById("entropyDetails").textContent = `${r.file || "File"} · ${r.status || "Analyzed"}`;
        setStage("entropyStage", "ACTIVE");
    } catch (e) {
        document.getElementById("entropy").textContent = "Unavailable";
        document.getElementById("entropyDetails").textContent = "Entropy service unavailable";
        setStage("entropyStage", "ERROR"); console.error(e);
    }
}
async function refreshDownloads() {
    const table = document.getElementById("downloadsTable");
    const summary = document.getElementById("downloadsSummary");
    try {
        const data = await requestJSON("/api/downloads");
        const files = Array.isArray(data.files) ? data.files : [];
        table.replaceChildren();
        const newCount = Number(data.new_files_count || 0);
        const changedCount = Number(data.changed_files_count || 0);
        summary.textContent = `${files.length} recent file(s) inspected in ${data.folder || "Downloads"}. New arrivals in the last ${data.new_download_window_minutes || 15} minutes: ${newCount}; recently changed: ${changedCount}. VirusTotal: ${data.reputation_enabled ? "configured (manual per-file check)" : "API key not configured"}. Files are not uploaded.`;
        setStage("downloadStage", data.reputation_enabled ? "VT + MONITORING" : "LOCAL MONITORING");
        if (!files.length) return showTableMessage(table, 5, "No files found in Downloads.");
        files.forEach(file => {
            const row = table.insertRow();
            addCell(row, file.name);
            addCell(row, file.extension || "Unknown");
            addCell(row, file.size_human || "—");
            addCell(row, file.sha256 || "Unavailable");
            const displayAssessment = file.newly_seen
                ? `NEW DOWNLOAD · ${file.assessment || "NOT CHECKED"}`
                : (file.changed_recently
                    ? `RECENTLY CHANGED · ${file.assessment || "NOT CHECKED"}`
                    : (file.assessment || "Unknown"));
            const cell = addCell(row, displayAssessment);
            cell.style.fontWeight = "600";
            if (file.newly_seen) {
                cell.style.color = "#75c9ff";
                cell.title = "Observed in Downloads after SentinelDF started. Arrival alone is not evidence of malware.";
            } else if (file.changed_recently) {
                cell.style.color = "#ffbd69";
                cell.title = "File changed while SentinelDF was running; review if unexpected.";
            }
            if ((file.indicators || []).length) {
                cell.title = file.indicators.join("; ");
                if (!file.reputation_status || file.reputation_status === "not_checked") {
                    cell.style.color = "#ffbd69";
                }
            }
            if (file.reputation_status === "reported") {
                cell.title = `VirusTotal: ${file.malicious || 0} malicious, ${file.suspicious || 0} suspicious, ${file.harmless || 0} harmless, ${file.undetected || 0} undetected`;
                if ((file.malicious || 0) > 0) cell.style.color = "#ff6b6b";
                else if ((file.suspicious || 0) > 0) cell.style.color = "#ffbd69";
                else cell.style.color = "#8fd3a8";
            } else if (file.reputation_status === "not_found") {
                cell.style.color = "#9ca3af";
            } else if (file.reputation_status === "error") {
                cell.style.color = "#ffbd69";
                if (file.vt_link) {
                    const link = document.createElement("a");
                    link.href = file.vt_link;
                    link.target = "_blank";
                    link.rel = "noopener noreferrer";
                    link.textContent = " View report";
                    link.style.marginLeft = "8px";
                    link.style.color = "inherit";
                    cell.appendChild(link);
                }
            }
            const button = document.createElement("button");
            button.type = "button";
            button.className = "btn-secondary";
            button.textContent = file.reputation_status === "reported" || file.reputation_status === "not_found" ? "Recheck VT" : "Check VT";
            button.style.marginLeft = "8px";
            button.style.padding = "6px 9px";
            button.disabled = !data.reputation_enabled || !/^[a-f0-9]{64}$/i.test(file.sha256 || "");
            button.title = data.reputation_enabled
                ? "Look up this SHA-256 hash in VirusTotal; the file itself is not uploaded."
                : "Configure VIRUSTOTAL_API_KEY in Windows, then restart SentinelDF.";
            button.addEventListener("click", async () => {
                const previousText = button.textContent;
                button.disabled = true;
                button.textContent = "Checking…";
                try {
                    const response = await fetch("/api/virustotal/check", {
                        method: "POST",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({sha256: file.sha256})
                    });
                    const result = await response.json();
                    if (!response.ok) {
                        summary.textContent = `VirusTotal lookup: ${result.message || `HTTP ${response.status}`}`;
                    } else {
                        summary.textContent = `${file.name}: ${result.reputation || "VirusTotal checked"} — ${result.message || "Hash lookup complete."}`;
                    }
                    await refreshDownloads();
                    await refreshAlerts();
                } catch (error) {
                    summary.textContent = `VirusTotal lookup failed: ${error.message}`;
                } finally {
                    button.textContent = previousText;
                    button.disabled = false;
                }
            });
            cell.appendChild(button);
        });
    } catch (e) {
        summary.textContent = "Download inspection API unavailable. Update app.py first.";
        showTableMessage(table, 5, "Could not load download inspection.");
        setStage("downloadStage", "ERROR"); console.error(e);
    }
}
async function refreshProcesses() {
    const card = document.getElementById("processStatus");
    const table = document.getElementById("processTable");
    const inventoryStatus = document.getElementById("processInventoryStatus");
    const summary = document.getElementById("processSummary");
    try {
        const data = await requestJSON("/api/processes");
        if (data.status !== "success") throw new Error(data.message || "Process analysis failed");
        const processes = Array.isArray(data.processes) ? data.processes : [];
        if (card) card.textContent = `Connected (${processes.length})`;
        if (inventoryStatus) inventoryStatus.textContent = "CONNECTED";
        if (summary) summary.textContent = `Showing ${processes.length} process records. Observe-only inventory; not a full malware scan.`;
        setStage("processStage", "CONNECTED");
        table.replaceChildren();
        if (!processes.length) return showTableMessage(table, 6, "No process records returned.");
        processes.forEach(proc => {
            const row = table.insertRow();
            addCell(row, proc.name || "Unknown");
            addCell(row, proc.pid ?? "—");
            addCell(row, proc.executable || "Not available");
            const exe = String(proc.executable || "").toLowerCase().replaceAll("/", "\\");
            const name = String(proc.name || "").toLowerCase();
            let indicator = "No basic indicator";
            if (!exe) indicator = "Executable path unavailable";
            else if (exe.includes("\\temp\\") || exe.includes("\\appdata\\local\\temp\\")) indicator = "HIGH REVIEW: temp path";
            else if (exe.includes("\\downloads\\")) indicator = "REVIEW: Downloads path";
            else if (["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"].includes(name)) indicator = "Dual-use utility — review context";
            const cell = addCell(row, indicator);
            if (indicator !== "No basic indicator") cell.style.color = indicator.startsWith("HIGH") ? "#ff6b6b" : "#ffbd69";
            const reputationCell = row.insertCell();
            reputationCell.style.padding = "12px"; reputationCell.style.borderTop = "1px solid #263149";
            if (exe && /\.(exe|dll|scr|com)$/i.test(exe)) {
                const checkBtn = document.createElement("button"); checkBtn.className = "btn-secondary"; checkBtn.textContent = "Check VT";
                checkBtn.title = "Hash this running executable and look up its SHA-256; file is not uploaded.";
                checkBtn.addEventListener("click", async () => {
                    checkBtn.disabled = true; checkBtn.textContent = "Checking…";
                    try {
                        const response = await fetch("/api/processes/check-reputation", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({path:proc.executable})});
                        const result = await response.json();
                        reputationCell.textContent = result.reputation || result.message || "Unknown";
                        reputationCell.style.color = result.severity === "HIGH" || result.malicious > 0 ? "#ff6b6b" : (result.severity === "MEDIUM" || result.suspicious > 0 ? "#ffbd69" : "#9ca3af");
                        if (result.link) { const link=document.createElement("a"); link.href=result.link; link.target="_blank"; link.rel="noopener noreferrer"; link.textContent=" Report"; reputationCell.appendChild(link); }
                        await refreshAlerts();
                    } catch (error) { reputationCell.textContent = `Lookup failed: ${error.message}`; }
                    finally { checkBtn.disabled = false; checkBtn.textContent = "Recheck VT"; }
                });
                reputationCell.appendChild(checkBtn);
            } else reputationCell.textContent = "Not an executable path / unavailable";
            addCell(row, proc.action || "Observe only");
        });
    } catch (e) {
        if (card) card.textContent = "Unavailable";
        if (inventoryStatus) inventoryStatus.textContent = "ERROR";
        if (summary) summary.textContent = "Could not retrieve process records.";
        setStage("processStage", "ERROR");
        showTableMessage(table, 5, "Process inventory is unavailable.");
        console.error(e);
    }
}
async function refreshWebsites() {
    const table = document.getElementById("websitesTable");
    const summary = document.getElementById("websiteSummary");
    try {
        const entries = await requestJSON("/api/websites");
        table.replaceChildren();
        setStage("websiteStage", entries.length ? "RECEIVING EVENTS" : "WAITING FOR EXTENSION");
        summary.textContent = `${entries.length} recent browser navigation event(s). Reputation is checked only when you click Check VT.`;
        if (!entries.length) return showTableMessage(table, 4, "No browser events yet. Install and enable the included extension.");
        entries.slice(0, 50).forEach(entry => {
            const row = table.insertRow();
            addCell(row, entry.time || "—");
            const siteCell = addCell(row, entry.url || entry.host || "Unknown URL");
            siteCell.style.maxWidth = "380px"; siteCell.style.overflowWrap = "anywhere";
            let reputationLabel = entry.reputation || "Not checked";
            if (entry.reputation_status === "reported" && (Number.isFinite(Number(entry.malicious)) || Number.isFinite(Number(entry.suspicious)))) {
                reputationLabel += ` (${Number(entry.malicious || 0)} malicious / ${Number(entry.suspicious || 0)} suspicious)`;
            }
            const reputationCell = addCell(row, reputationLabel);
            if (entry.severity === "HIGH") reputationCell.style.color = "#ff6b6b";
            else if (entry.severity === "MEDIUM") reputationCell.style.color = "#ffbd69";
            else if (entry.reputation_status === "reported") reputationCell.style.color = "#8fd3a8";
            const actionCell = row.insertCell(); actionCell.style.padding = "12px"; actionCell.style.borderTop = "1px solid #263149";
            const button = document.createElement("button"); button.className = "btn-secondary"; button.textContent = "Check VT";
            button.addEventListener("click", async () => {
                button.disabled = true; button.textContent = "Checking…";
                try {
                    const response = await fetch("/api/websites/check", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url:entry.url})});
                    const result = await response.json();
                    if (!response.ok) { summary.textContent = result.message || "URL lookup failed."; }
                    await refreshWebsites(); await refreshAlerts();
                    if (result.link) window.open(result.link, "_blank", "noopener,noreferrer");
                } catch (error) { summary.textContent = `Website lookup failed: ${error.message}`; }
                finally { button.disabled = false; button.textContent = "Check VT"; }
            });
            actionCell.appendChild(button);
        });
    } catch (e) { setStage("websiteStage", "ERROR"); summary.textContent = "Website monitor API unavailable."; }
}
async function refreshAlerts() {
    const panel = document.getElementById("alertsList");
    try {
        const alerts = await requestJSON("/api/alerts");
        panel.replaceChildren();
        if (!Array.isArray(alerts) || !alerts.length) {
            const icon = document.createElement("div"); icon.className = "empty-icon"; icon.textContent = "✓";
            const heading = document.createElement("strong"); heading.textContent = "No alerts recorded";
            const msg = document.createElement("p"); msg.textContent = "No activity has met the configured combined detection rule.";
            panel.append(icon, heading, msg); setStage("alertStage", "READY"); return;
        }
        setStage("alertStage", "ALERTS");
        alerts.forEach(alert => {
            const card = document.createElement("div");
            card.style.cssText = "text-align:left;padding:14px;margin:10px 0;border:1px solid #664b32;border-radius:8px;";
            const h = document.createElement("strong"); h.textContent = `${alert.severity || "NOTICE"}: ${alert.title || "Security alert"}`;
            const t = document.createElement("p"); t.textContent = alert.timestamp || "";
            const m = document.createElement("p"); m.textContent = alert.message || "";
            const s = document.createElement("small"); s.textContent = alert.status || "Needs review";
            card.append(h, t, m, s); panel.appendChild(card);
        });
    } catch (e) { console.error(e); setStage("alertStage", "ERROR"); }
}
async function refreshDashboard() {
    await Promise.allSettled([refreshStatus(), refreshEvents(), refreshEntropy(), refreshProcesses(), refreshAlerts(), refreshDownloads(), refreshWebsites()]);
}
startBtn.addEventListener("click", async () => {
    startBtn.disabled = true; statusDescription.textContent = "Starting watcher...";
    try { await requestJSON("/api/start", {method:"POST"}); await refreshDashboard(); }
    catch (e) { statusDescription.textContent = `Start failed: ${e.message}`; startBtn.disabled = false; console.error(e); }
});
stopBtn.addEventListener("click", async () => {
    stopBtn.disabled = true;
    try { await requestJSON("/api/stop", {method:"POST"}); await refreshDashboard(); }
    catch (e) { statusDescription.textContent = `Stop failed: ${e.message}`; stopBtn.disabled = false; console.error(e); }
});
document.getElementById("refreshDownloadsBtn")?.addEventListener("click", refreshDownloads);
refreshDashboard();
setInterval(refreshDashboard, 3000);


// Shodan InternetDB + VirusTotal IP reputation. Manual, authenticated lookups only.
(() => {
    const form = document.getElementById("shodanForm");
    const input = document.getElementById("shodanIp");
    const status = document.getElementById("shodanStatus");
    const results = document.getElementById("shodanResults");
    if (!form || !input || !status || !results) return;

    const makeText = (tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value == null || value === "" ? "None reported" : String(value);
        return node;
    };
    const addLine = (parent, label, value) => {
        const line = document.createElement("p");
        const strong = document.createElement("strong");
        strong.textContent = label + ": ";
        line.append(strong, makeText("span", Array.isArray(value) ? (value.length ? value.join(", ") : "None reported") : value));
        parent.appendChild(line);
    };

    form.addEventListener("submit", async event => {
        event.preventDefault();
        const ip = input.value.trim();
        status.textContent = "Checking Shodan InternetDB and VirusTotal IP reputation…";
        results.replaceChildren();
        const button = form.querySelector('button[type="submit"]');
        if (button) { button.disabled = true; button.textContent = "Checking…"; }
        try {
            const response = await fetch("/api/intel/ip", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({ip})
            });
            const data = await response.json();
            if (!response.ok || data.status !== "success") {
                status.textContent = data.message || "Lookup failed.";
                return;
            }

            const shodan = data.shodan || {};
            const vt = data.reputation || {};
            status.textContent = `Lookup completed for ${data.ip}. Review both sources; results are not a definitive safety verdict.`;

            const shodanCard = document.createElement("div");
            shodanCard.style.cssText = "padding:14px;margin:10px 0;border:1px solid #263149;border-radius:8px;";
            shodanCard.appendChild(makeText("h4", "Shodan InternetDB"));
            addLine(shodanCard, "Status", shodan.status);
            addLine(shodanCard, "Ports", shodan.ports);
            addLine(shodanCard, "Hostnames", shodan.hostnames);
            addLine(shodanCard, "Tags", shodan.tags);
            addLine(shodanCard, "CPEs", shodan.cpes);
            addLine(shodanCard, "Potential CVEs", shodan.vulns);
            shodanCard.appendChild(makeText("small", shodan.message || ""));
            results.appendChild(shodanCard);

            const vtCard = document.createElement("div");
            vtCard.style.cssText = "padding:14px;margin:10px 0;border:1px solid #263149;border-radius:8px;";
            vtCard.appendChild(makeText("h4", "VirusTotal IP Reputation"));
            addLine(vtCard, "Status", vt.status);
            addLine(vtCard, "Reputation", vt.reputation || vt.message);
            if (vt.status === "reported" || vt.status === "not_found") {
                addLine(vtCard, "Malicious", vt.malicious ?? 0);
                addLine(vtCard, "Suspicious", vt.suspicious ?? 0);
                addLine(vtCard, "Harmless", vt.harmless ?? 0);
                addLine(vtCard, "Undetected", vt.undetected ?? 0);
            }
            vtCard.appendChild(makeText("small", vt.message || ""));
            if (vt.link) {
                const link = document.createElement("a");
                link.href = vt.link; link.target = "_blank"; link.rel = "noopener noreferrer";
                link.textContent = "Open VirusTotal IP report";
                link.style.cssText = "display:inline-block;margin-top:10px;color:#75c9ff;";
                vtCard.appendChild(link);
            }
            results.appendChild(vtCard);
        } catch (error) {
            status.textContent = `Lookup failed: ${error.message}`;
        } finally {
            if (button) { button.disabled = false; button.textContent = "Check IP"; }
        }
    });
})();
