# Gmail Security Scanner

A PoC Gmail Add-on designed to provide real time maliciousness analysis for incoming emails. This project utilizes a Google Apps Script frontend integrated directly into the Gmail UI and a Python based analysis engine hosted on Google Cloud.


I wanted to share a bit about how this project came together. Rather than just following a spec, I approached this as a personal challenge to understand what actually happens when a "bad" email hits an inbox and how we can catch it without making the user's life difficult.

## The Process

I spent the first few hours researching the anatomy of modern phishing. To get it right, I actually spent time viewing a dataset of real-world malicious emails to understand exactly what was triggering the red flags in those specific cases.

* **The Investigation:** By looking at actual malicious samples, I identified that the threat is rarely just a "virus" in a file; it's usually a clever mix of technical tricks and psychological pressure.

* **A "Wow" Moment:** One thing that really surprised me was seeing **XSS (Cross-Site Scripting)** payloads inside email headers. I've seen XSS in web apps a thousand times, but I hadn't deeply considered it within the scope of an email client. It made me realize that the email itself is a vector for attacking the tool used to read it.
* **Resilience:** I saw how malformed text encodings could be used to crash scanners, which led me to build a robust "fallback" system (UTF-8/Latin-1) for my engine to ensure it wouldn't break when encountering intentionally messy data.

## Architecture

When it came time to build, I chose to split the work between a **Google Apps Script** frontend and a **Python (Flask)** backend.

* **Learning the Stack:** This was my first time using Google Apps Script and Google Cloud. I'm not a designer, and Apps Script involves a lot of frontend work, but once I "caught" the logic of how it renders cards, it was a satisfying, yet not exactly "fun".
* **Cloud Transition:** While Google Cloud was new to me, I found the logic wasn't much different from Azure or AWS, which made the deployment of the backend analysis engine quite smooth.


## Designing for Clarity

My first sketches were plain text, but I quickly realized that security verdicts need visual urgency. I added colors and a clear hierarchy so that a "Red" warning communicates risk instantly, ensuring the user understands the threat at a glance.

## What's Next?

If I had more time to keep digging, here is where I'd go next to make the engine even harder to trick:

* **Deep Security Research**: Spend more time analyzing emerging malicious mail trends to build more sophisticated, context-aware checks.

* **Server-Side Hardening**: Implement stricter rate limiting, OIDC authentication, and deeper input sanitization to further protect the analysis engine.
* **Extended QA & Testing**: Build a comprehensive automated test suite with a larger library of malicious `.eml` samples to ensure 100% edge-case coverage.

* **VirusTotal API Integration**: Connect the backend to VirusTotal to automatically cross-reference discovered URLs and attachment hashes against global threat intelligence databases.

* **Magic Bytes Check**: Go beyond file extensions to verify true file headers (MIME sniffing) to catch masked executables.
* **Urgency Keyword Engine**: Flag high-pressure language patterns common in social engineering and Business Email Compromise (BEC).

---

## The Email Analysis Engine

The backend performs a multi-layered heuristic scan to identify security red flags.

### 1. Data Parsing & Normalization
* **EML Parsing:** Converts raw bytes or strings into structured `EmailMessage` objects using the `email.policy.default` standard.
* **Body Extraction:** Safely extracts `text/plain` and `text/html` parts. It utilizes a robust decoding strategy (UTF-8 with a Latin-1 fallback) to ensure the engine never crashes on malformed or non-standard encodings.
* **Quoted-Printable Decoding:** Decodes content within the hidden link check to ensure links obscured by email transfer encoding are correctly analyzed.

### 2. Heuristic Security Checks
* **Header Injection Detection:** Scans the raw header section for XSS patterns and script tags (`<script>`, `onerror`, etc.) to prevent malicious payloads from impacting the Add-on UI.
* **Deep Attachment Analysis:** * Flags known dangerous extensions (e.g., `.exe`, `.msi`, `.js`).
    * Detects **Double Extension Spoofing** (e.g., `invoice.pdf.exe`) by validating the second-to-last file suffix.
* **Hidden Link Identification:** Uses **BeautifulSoup** to compare the visible text of a link with its actual `href` destination. It flags instances where the visible text looks like a URL but points to a different domain.
* **Authentication Header Analysis:** Inspects `Authentication-Results` and `Received-SPF` headers for **SPF, DKIM, and DMARC** status. It penalizes failures or missing records based on configurable weights.
* **Sender Mismatch:** Compares the `From` address with the `Reply-To` address to detect response-diversion tactics used in spoofing.
* **Link Density & Obfuscation:** * Penalizes emails exceeding a specific link count threshold (`MAX_LINK_THRESHOLD`).
    * Scans URLs for known link-shortener domains (e.g., `bit.ly`, `tinyurl`) used to hide malicious destinations.

### 3. Orchestration & Scoring
* **Aggregated Scoring:** Sums the results of all individual checks into a unified risk value.
* **Normalization:** Ensures the final score is bounded between `MIN_SCORE` and `MAX_SCORE`.
* **Alert Generation:** Returns a list of specific check names that contributed to the score for user transparency.

## Final Thoughts

I am incredibly proud of what I've achieved with this project, both in the depth of the initial research and the quality of the final development. I learned a tremendous amount throughout this process from navigating the nuances of the Google Workspace ecosystem to hardening a backend against adversarial inputs. It was a great dive into the cat-and-mouse game of email security. It's fully set up and ready to run against a real Gmail account, and I'm looking forward to walking you through the logic and the trade-offs I made along the way.

