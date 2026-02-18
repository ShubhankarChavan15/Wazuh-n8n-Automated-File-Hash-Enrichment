# Wazuh-n8n-Automated-File-Hash-Enrichment
Receive Wazuh syscheck (file-integrity) alerts → extract hash (sha256/md5/sha1) → query VirusTotal → build summary with detection stats and metadata → render HTML report → if Suspicious → create ServiceNow incident + post to Slack; else archive/email.
