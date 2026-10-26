
# 🔐 Phishing Link Detector

A beginner-friendly Python cybersecurity project that checks URLs
for common phishing warning signs.

## Features

- Detects IP-address hostnames
- Flags selected URL-shortening services
- Checks for potentially deceptive keywords
- Warns about HTTP connections
- Explains detected warning signs
- Runs locally without third-party packages

## Requirements

- Python 3.10 or later

## How to Run

Open a terminal in the project folder and run:

```bash
py phishing_detector.py
```

Enter a URL to analyse. Type `quit` to exit.

## Limitations

This project uses rule-based checks. It does not use AI or query a
live threat-intelligence database.

A warning does not prove a URL is malicious, and no warning does
not prove a URL is safe. HTTPS alone does not guarantee legitimacy.

Never enter passwords or sensitive information on suspicious sites.

## Future Improvements

- Add automated unit tests
- Improve URL validation
- Explore threat-intelligence APIs
- Experiment with machine-learning-based URL classification

## Author

ENIWAIYE AYOBAMI

Artificial Intelligence student | FUTMINNA
