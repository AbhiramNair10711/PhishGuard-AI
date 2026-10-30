# 🛡️ PhishGuard AI — Explainable Phishing Risk Assessment

PhishGuard AI is a Streamlit web application that analyses suspicious URLs and message text for common phishing warning signs. It uses a transparent, Mamdani-style fuzzy inference engine to convert heuristic signals into an estimated risk score, then explains the warning signs behind the result.

> **Educational prototype:** This application is not a replacement for professional security software. A low score does not prove that a URL or message is safe, and a high score does not prove that it is malicious.

## Features

- **URL analysis:** checks for characteristics such as non-HTTPS URLs, IP-address hosts, unusually long URLs, URL shorteners, many subdomain levels, `@` characters, and suspicious terms.
- **Message analysis:** detects urgency, threats, requests for credentials/OTPs, deceptive phrases, repeated exclamation marks, and embedded URLs.
- **Explainable risk score:** returns a 0–100 estimate and Low, Medium, High, or Critical category.
- **Fuzzy inference:** includes membership functions, Mamdani-style rules, rule aggregation, and centroid defuzzification.
- **Analysis history:** stores recent analyses in a local SQLite database.
- **Statistics dashboard:** visualises risk-category counts and average risk over time.
- **Privacy-minded design:** submitted URLs are analysed as text and are not opened or fetched.

## Screenshots

Add screenshots of your running app here, for example:

```text
docs/screenshots/home.png
docs/screenshots/analysis-result.png
docs/screenshots/statistics.png
```

## Technology stack

- Python
- Streamlit
- NumPy
- Pandas
- Plotly
- SQLite

The fuzzy engine is implemented in `fuzzy_engine.py`, so no separate fuzzy-logic package is required.

## Project structure

```text
PhishGuard-AI/
├── app.py
├── fuzzy_engine.py
├── url_analyzer.py
├── message_analyzer.py
├── database.py
├── requirements.txt
├── .gitignore
├── README.md
└── data/
```

## Requirements

- Python 3.10 or newer
- pip
- A modern browser

## Run locally

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/PhishGuard-AI.git
cd PhishGuard-AI
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start Streamlit

```bash
streamlit run app.py
```

Streamlit will print a local address, usually `http://localhost:8501`. Open it in your browser.

## How the risk engine works

### 1. Feature extraction

The URL and message analyzers create four numerical inputs, each on a 0–100 scale:

| Input | Meaning |
|---|---|
| URL suspicion | Heuristic URL characteristics |
| Urgency | Pressure, threats, or time-limited language |
| Sensitive-data request | References to passwords, OTPs, PINs, or account verification |
| Deceptive language | Commonly abused persuasive phrases |

These are heuristic signals, not a verified threat-intelligence feed.

### 2. Fuzzification

Each input is mapped to Low, Medium, and High membership values. Overlapping membership functions allow a signal to partially belong to more than one category.

### 3. Mamdani-style rule evaluation

Example rules include:

- IF all signals are Low, THEN risk is Low.
- IF moderate signals are present, THEN risk may be Medium.
- IF URL suspicion combines with urgency or deception, THEN risk is High.
- IF multiple strong signals occur together, THEN risk is Critical.

The implementation uses minimum for rule antecedents and maximum to aggregate the clipped output membership functions.

### 4. Centroid defuzzification

The aggregated output is converted into one score between 0 and 100 using the centroid of area.

### 5. Verdict

The score is mapped to display categories:

- `0–24`: Low
- `25–49`: Medium
- `50–74`: High
- `75–100`: Critical

These are project-defined thresholds, not industry-standard boundaries.

## Test the application

Try the built-in sample messages and URLs, then test additional cases:

- A normal meeting reminder with no URL.
- An unexpected message asking for an OTP.
- A URL with an IP-address host.
- A long URL containing multiple suspicious terms.
- A legitimate HTTPS URL with a path containing the word `login`.
- A message containing both urgency and a suspicious URL.

Record false positives and false negatives during testing. Avoid using real credentials or private messages.

## Deploy on Streamlit Community Cloud

1. Push this project to a GitHub repository.
2. Sign in to Streamlit Community Cloud.
3. Create a new app and select your repository.
4. Set the main file path to `app.py`.
5. Deploy.

The SQLite database is suitable for local demonstrations. Some hosted environments may not preserve local database files across restarts or redeployments. For persistent hosted history, use a managed database and appropriate privacy controls.

## Limitations and responsible use

- The app does not open URLs, follow redirects, inspect website content, or check live domain reputation.
- HTTPS alone does not mean a website is trustworthy; HTTP alone does not prove phishing.
- Keyword-based checks can miss novel attacks and can flag legitimate messages.
- The fuzzy risk score is a heuristic estimate, not a calibrated real-world probability.
- The current implementation does not train a classifier on a labelled dataset.
- Do not submit real passwords, OTPs, bank details, or confidential messages.
- Verify unexpected requests using a trusted, independently obtained contact method.

## Future improvements

- Train a Naïve Bayes text classifier using a labelled phishing/SMS dataset.
- Add precision, recall, F1-score, and a confusion matrix.
- Add a carefully curated, regularly updated threat-intelligence feed.
- Add file export for analysis reports.
- Improve URL parsing and feature explanations.
- Add automated unit tests and CI.

## Academic alignment

This project primarily demonstrates Intelligent Systems II topics from **Fuzzy Inference Systems**:

- Fuzzy sets and membership functions
- Fuzzification
- Fuzzy IF–THEN rules
- Mamdani inference
- Rule aggregation
- Centroid defuzzification
- Reasoning under uncertainty

A Naïve Bayes classifier can be added as a separate extension if the project scope permits.

## License

This project is intended for educational use. Add a license file (for example, MIT) if you want to permit reuse and redistribution.

## How domain analysis and verdict selection work

PhishGuard uses `tldextract` with its bundled Public Suffix List (PSL) snapshot to parse domain names. This recognizes ordinary suffixes such as `.com`, `.net`, `.org`, `.in` and multi-part public suffixes such as `.co.in` and `.co.uk` without manually maintaining a hard-coded list in the analyzer. The app runs without fetching a suffix list on every analysis; updating the `tldextract` package updates its bundled snapshot.

For each URL, the analyzer reports the hostname, registrable domain, public suffix, TLD, subdomain, and whether the suffix is recognized. It then checks several explainable signals: IP-address hosts, missing/unrecognized suffixes, invalid hostname formatting, punycode/IDN labels, unusually long or digit-heavy registered labels, excessive subdomain levels, higher-scrutiny suffixes, missing HTTPS, URL length, `@` in the authority, known shorteners, hyphens, percent encoding, and persuasive/sensitive terms in the URL.

**A domain extension does not determine the verdict by itself.** `.com`, `.net`, `.org`, `.in`, and other suffixes are not automatically trusted or suspicious. A higher-scrutiny suffix adds only a small contextual score, and can never prove phishing. Domain and URL signals produce `url_suspicion` (0–100). The fuzzy engine then combines that value with message urgency, sensitive-data requests, and deception using Mamdani-style fuzzy rules and centroid defuzzification. The final score is classified as Low, Medium, High, or Critical.

This remains a heuristic educational prototype: it does not check domain age, live DNS, certificate reputation, URL blocklists, website content, or a threat-intelligence API. A low score is not proof that a website is safe, and a high score is not definitive proof of phishing.
