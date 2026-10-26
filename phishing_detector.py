
from urllib.parse import urlparse
import ipaddress
import re

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
}

SUSPICIOUS_WORDS = {
    "login",
    "verify",
    "urgent",
    "password",
    "account",
    "update",
    "wallet",
    "claim",
    "bonus",
}


def analyse_url(raw_url):
    """Check a URL for common phishing warning signs."""
    raw_url = raw_url.strip()

    if not raw_url:
        return ["No URL was entered."]

    candidate = (
        raw_url if "://" in raw_url else "https://" + raw_url
    )

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname:
            return ["Invalid URL: no hostname found."]

        hostname = hostname.lower().rstrip(".")
        warnings = []

        if parsed.scheme.lower() not in {"http", "https"}:
            warnings.append("Unusual URL scheme.")

        if parsed.username is not None or parsed.password is not None:
            warnings.append(
                "The URL contains user information before @. "
                "Check the destination carefully."
            )

        try:
            ipaddress.ip_address(hostname)
            warnings.append(
                "The hostname is an IP address, not a domain name."
            )
        except ValueError:
            pass

        if "xn--" in hostname:
            warnings.append(
                "The domain contains punycode. Inspect its spelling."
            )

        if hostname in SHORTENERS:
            warnings.append(
                "This uses a URL-shortening service that hides "
                "the final destination."
            )

        url_text = (
            hostname + parsed.path + "?" + parsed.query
        ).lower()

        found_words = sorted(
            word
            for word in SUSPICIOUS_WORDS
            if re.search(
                rf"(?<![a-z]){re.escape(word)}(?![a-z])",
                url_text,
            )
        )

        if found_words:
            warnings.append(
                "Potentially deceptive keywords found: "
                + ", ".join(found_words)
            )

        if len(hostname) > 50:
            warnings.append("The hostname is unusually long.")

        if hostname.count("-") >= 3:
            warnings.append("The hostname contains several hyphens.")

        if parsed.scheme.lower() == "http":
            warnings.append(
                "Uses HTTP instead of HTTPS. HTTPS provides "
                "transport encryption, but does not guarantee safety."
            )

        if not warnings:
            warnings.append(
                "No basic warning signs detected. "
                "This does not prove the URL is safe."
            )

        return warnings

    except (ValueError, UnicodeError):
        return ["Could not analyse this URL. Check its format."]


def main():
    print("=" * 45)
    print("       PHISHING LINK DETECTOR")
    print("=" * 45)
    print("Offline URL warning checks")
    print("Never enter passwords on suspicious websites.\n")

    while True:
        url = input("Enter a URL, or type quit to exit: ")

        if url.strip().lower() == "quit":
            print("Goodbye. Stay safe online!")
            break

        warnings = analyse_url(url)

        print("\nAnalysis:")
        for warning in warnings:
            print(f"- {warning}")

        print("\nRemember: these checks cannot confirm whether "
              "a website is legitimate or malicious.")
        print("-" * 45)


if __name__ == "__main__":
    main()
