# Phishing Investigation: "Cloud Services" Account-Deletion Lure

> SOC analyst style investigation of a phishing email impersonating a cloud storage provider, from initial triage through infrastructure pivoting, sandboxed URL detonation and MITRE ATT&CK mapping.

**Sample source:** Real captured phishing email from [PhishingPot](https://github.com/rf-peixoto/phishing_pot) | **Verdict:** Confirmed true-positive phishing | **Confidence on APT correlation:** Moderate (not confirmed attribution)

 [**Read the full investigation report →**](report/report.md)
 [Machine-readable IOC list (CSV) →](iocs/iocs.csv)


## Executive Summary

An email impersonating "Cloud Services" threatened permanent deletion of photos, backups, and shared documents unless the recipient clicked a "Recover My Account" link. What looked like a simple urgency based lure turned into a multi stage investigation that surfaced:

- Failed email authentication (SPF fail, no DKIM, no DMARC) and a spoofed display domain that didn't match the actual sending domain
- Sender and hosting infrastructure sitting on the same ASN (AS60781 / LeaseWeb Netherlands), an ASN with a documented history of hosting Qakbot, Cobalt Strike, Remcos RAT, AsyncRAT, RedLine Stealer and Mirai infrastructure
- A redirect chain and obfuscated URL scheme that when detonated in a sandbox (urlscan.io) revealed that the phishing site was conditionally serving a benign news RSS feed which is evidence of active cloaking rather than dead/inactive campaign
- A file hash from a related domain on the same infrastructure that correlates with CISA Advisory AA26-204a on Russian state linked phishing activity; flagged and treated as a **moderate confidence lead** not confirmed attribution

## Investigation Approach

| Stage                                | What I did                                                                                                                                  |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Visual/content triage**         | Identified social engineering tactics: urgency language, fake ticket references, spoofed footer address                                     |
| **2. Sender verification**           | Confirmed the sender company/address didn't correspond to any real entity                                                                   |
| **3. Header analysis**               | Reconstructed mail path, confirmed SPF/DKIM/DMARC failure and domain spoofing                                                               |
| **4. Infrastructure & threat intel** | Pivoted on sender IP → ASN → passive DNS → related domains and malware families (VirusTotal, AbuseIPDB, ThreatFox, URLhaus, AlienVault OTX) |
| **5. URL/body analysis**             | Decoded the obfuscated link structure and traced it to the actual phishing hosting IP                                                       |
| **6. Sandbox detonation**            | Ran the live link through urlscan.io to observe real HTTP behavior and redirect logic                                                       |
| **7. Attribution**                   | Correlated a resource hash to a CISA advisory, explicitly caveated as moderate confidence                                                   |
| **8. MITRE ATT&CK mapping**          | Mapped observed behavior to five ATT&CK techniques                                                                                          |
| **9. Recommendations**               | Delivered concrete containment and user-awareness actions                                                                                   |

## Key Findings

| Category             | Finding                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| Email authentication | SPF: Fail · DKIM: None · DMARC: None                                                               |
| Domain spoofing      | `From:` displayed `CloudServicesi7t.com`, actual sending domain `terbsx.onmicrosoft.com`           |
| Sender IP            | `62.212.79.196` (AS60781, LeaseWeb NL) - 6 prior AbuseIPDB reports                                 |
| Phishing hosting IP  | `95.211.62.162` -> resolved from an obfuscated numeric host string in all email links              |
| Hosting ASN          | AS60781 -> linked to Qakbot, Cobalt Strike, Remcos RAT, AsyncRAT, RedLine Stealer, Mirai           |
| Attribution lead     | File hash correlates with CISA AA26-204a (Russian state-linked phishing); moderate confidence only |

## MITRE ATT&CK Techniques Observed

`T1566.002` Spearphishing Link · `T1585.001` Establish Accounts · `T1071.001` Web Protocols · `T1204.001` User Execution: Malicious Link · `T1090` Proxy/Redirect Infrastructure

## Tools Used

VirusTotal · AbuseIPDB · Cisco Talos · Spamhaus · AlienVault OTX (ThreatFox) · URLhaus · urlscan.io · WHOIS · Google/OSINT search · CISA advisories

## Repo Structure

```
soc-phishing-investigation-cloudservices/
├── README.md          <- this file
├── report/report.md   <- full 12-section investigation writeup
├── images/             <- screenshots referenced in the report
├── iocs/iocs.csv       <- machine-readable IOC list
└── LICENSE
```

## About / Source & Disclaimer

The email analyzed in this report is a **real, captured phishing sample** sourced from [PhishingPot](https://github.com/rf-peixoto/phishing_pot), an open-source repository of real world phishing emails collected for research and detection engineering purposes. The investigation, pivoting, sandboxing, and analysis in this report are my own independent work, conducted to build and demonstrate hands-on SOC analyst skills; this was not affiliated with, sent to, or targeted at any organization I'm part of.

Anything other than confirmed attribution itself, must not be treated as attribution like the CISA/APT correlation in Section 9 which is a moderate confidence lead based on the single hash on shared infrastructure.

I am open to feedback and corrections via issues or pull requests. Happy hunting!
