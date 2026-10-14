\# SentinelDF — Security Monitoring Platform



SentinelDF is a Python Flask-based security monitoring project designed to help explore file activity monitoring, ransomware detection heuristics, and threat intelligence through a web dashboard.



\## Features



\- \*\*File Activity Monitoring:\*\* Monitor file-related activity for suspicious behavior.

\- \*\*Ransomware Detection:\*\* Use entropy analysis and detection heuristics to identify potentially suspicious files.

\- \*\*Process Analysis:\*\* Inspect running processes for security analysis.

\- \*\*VirusTotal Integration:\*\* Check file, URL, and IP reputation when API access is configured.

\- \*\*Shodan InternetDB:\*\* Retrieve publicly available IP intelligence, including ports and known vulnerabilities when available.

\- \*\*Web Dashboard:\*\* View security monitoring information through a Flask application.

\- \*\*Authentication:\*\* Login, signup, and password recovery pages.

\- \*\*Browser Extension:\*\* Website monitoring functionality through a browser extension.



\## Technology Stack



\- Python

\- Flask

\- HTML, CSS, and JavaScript

\- VirusTotal API

\- Shodan InternetDB

\- Browser extension APIs



\## Getting Started



1\. Install Python 3.

2\. Open a terminal in the project directory.

3\. Install the required Python packages using your project's dependency list.

4\. Configure the required environment variables.

5\. Start the Flask application using the appropriate command for your setup.

6\. Open `http://127.0.0.1:5000` in your browser.



\## Configuration



Configure credentials through environment variables rather than hardcoding them in source files.



Examples of supported configuration variables include:



\- `SENTINELDF\_SECRET\_KEY`

\- `SENTINELDF\_EMAIL\_FROM`

\- `SENTINELDF\_EMAIL\_TO`

\- `SENTINELDF\_EMAIL\_APP\_PASSWORD`

\- `VIRUSTOTAL\_API\_KEY`



Some integrations require credentials and may be unavailable until configured.



\## Security Notice



This is a security monitoring and learning project. Detection results are heuristic and should not be treated as proof that a file or process is malicious or safe.



Use it only on systems and networks you own or are authorized to monitor. Do not publish API keys, passwords, session secrets, or other sensitive information.



\## Project Status



This project is under development. Detection accuracy, integration coverage, and monitoring capabilities may vary depending on configuration and environment.

