SentinelDF — Three Detection Improvements
========================================

This update adds the three requested areas to the EXISTING dashboard:
1) Suspicious executable detection: flags executable/script-capable downloads, double extensions, and a Windows MZ executable header that does not match the extension.
2) Running application review: adds context indicators for processes launched from Downloads/Temp and selected dual-use Windows utilities. The process table also has a per-process Check VT button for accessible EXE/DLL/SCR/COM files.
3) Website monitoring: adds a Website Monitor panel and an optional Chrome/Edge extension that records top-level HTTP(S) navigations into the local dashboard. Clicking Check VT looks up an EXISTING VirusTotal URL report only; URLs are not submitted.

IMPORTANT LIMITS
- These are triage/reputation signals, not a full antivirus engine or guaranteed malware verdict.
- A path or extension indicator alone does not prove maliciousness. Unknown/no report does not mean safe.
- Process reputation checks hash the executable and query the hash; the file is not uploaded. They may fail if Windows denies access.
- VirusTotal free-tier rate limits apply; the existing 16-second delay between new file hash lookups is retained.
- Website history and results are kept in memory and reset when SentinelDF restarts.
- The extension observes only top-level HTTP(S) navigations after it is installed/enabled. It does not block sites, inspect page contents, or monitor other browsers.
- Website reputation is manual (Check VT) to avoid automatically sending every URL to a third party. Only existing reports are queried; unknown URLs remain unknown.
- Nothing is killed, deleted, quarantined, or blocked. Process actions remain observe-only.

INSTALL THE DASHBOARD UPDATE
1. Stop SentinelDF in its Command Prompt with Ctrl+C.
2. In your project folder C:\Users\omkar\Desktop\RansomwareDetector, make a copy of app.py, static\script.js, and templates\index.html as backups.
3. Extract this ZIP. Copy app.py into your project root; copy static\script.js into your project's static folder; copy templates\index.html into your project's templates folder. Overwrite those three files when asked. Do not replace your style.css or other detector modules.
4. Start SentinelDF as usual:
   cd /d C:\Users\omkar\Desktop\RansomwareDetector
   venv\Scripts\activate
   set VIRUSTOTAL_API_KEY=YOUR_EXISTING_REAL_KEY
   python app.py
   If the key is already set in this same CMD window, do not replace it with a placeholder. Never share your API key.
5. Open http://127.0.0.1:5000 and refresh the dashboard.

INSTALL WEBSITE MONITOR (Chrome or Edge)
1. Keep SentinelDF running at http://127.0.0.1:5000.
2. Extract the ZIP fully to a normal folder. The extension folder is browser_extension.
3. Chrome: open chrome://extensions/ . Edge: open edge://extensions/ .
4. Turn on Developer mode.
5. Click Load unpacked and select the extracted browser_extension folder (the folder containing manifest.json).
6. Visit a normal HTTP/HTTPS website in a new tab, then return to SentinelDF. The Website Monitor table should show the navigation.
7. Click Check VT beside a website to look up an existing VirusTotal report.

TESTING
- Download Security: refresh the table and review executable/script-capable files and double-extension indicators.
- Applications & Live Process Inventory: review path/utility indicators; click Check VT beside an accessible executable. Respect the VirusTotal rate limit.
- Website Monitor: browse to a normal site, confirm it appears, and click Check VT. Do not visit known malicious sites to test this.

If an API key is missing/invalid or VirusTotal has no existing report, the result will say so. A no-report result is not a safe verdict.
