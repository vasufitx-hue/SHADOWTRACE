
import ipaddress
from urllib.parse import urlsplit

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
}

SUSPICIOUS_PATH_WORDS = {
    "login",
    "verify",
    "bank",
    "account",
    "kyc",
    "password",
    "payment",
}

def analyze_url(url: str) -> dict:
    """Inspect a URL and return suspicious indicators."""

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if any(character.isspace() for character in url):
        raise ValueError("URL cannot contain whitespace.")


    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname

        
        if not hostname:
            raise ValueError("URL must contain a hostname.")

        hostname = hostname.lower().rstrip(".")

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}") from error

    indicators = []

    
    try:
        ipaddress.ip_address(hostname)
        indicators.append("IP address used as hostname")
    except ValueError:
        pass


    if hostname in URL_SHORTENERS:
        indicators.append("Known URL shortening service")

    
    if "xn--" in hostname:
        indicators.append("Punycode domain detected")    
    if parsed.username is not None or parsed.password is not None:
        indicators.append("Credentials embedded in URL")

    
    if parsed.scheme.lower() == "http":
        indicators.append("Unencrypted HTTP connection")

  
    path = parsed.path.lower()

    for word in SUSPICIOUS_PATH_WORDS:
        if word in path:
            indicators.append(f"Suspicious path keyword: {word}")

    return {
        "original_url": url,
        "hostname": hostname,
        "scheme": parsed.scheme.lower(),
        "indicators": indicators,
        "indicator_count": len(indicators),
    }
