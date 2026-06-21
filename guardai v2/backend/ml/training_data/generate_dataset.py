"""
GuardAI ML — Training Data Generator

You don't have a labeled dataset yet (no database, no collected user
data — by design). This module generates a realistic training set by
programmatically constructing URLs that follow the same patterns real
phishing campaigns and real legitimate sites actually use, rather than
random strings. This is a standard, legitimate bootstrapping technique
for a v1 model (sometimes called "weak supervision" / rule-derived
labels) when no hand-labeled corpus exists.

IMPORTANT — read this before treating the model as "done":
This is a reasonable starting point, not a substitute for real labeled
data. Once you have production traffic, the highest-value next step is
swapping this synthetic set for real outcomes (e.g. URLs your threat-intel
providers confirmed as phishing vs. URLs that were repeatedly visited
with no incident) — see ml/README.md for the retraining path.

Brand list and TLD list deliberately reuse the same sources as
core/domain_analysis.py so the ML model and the rules engine are learning
from a consistent view of what "looks like a brand" or "looks risky".
"""

import random

random.seed(42)  # reproducible dataset across re-runs

BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "google",
    "facebook", "instagram", "twitter", "linkedin", "bankofamerica",
    "chase", "wellsfargo", "coinbase", "binance", "metamask", "opensea",
    "paytm", "hdfc", "icici", "sbi", "axis", "ebay", "dropbox", "adobe",
]

LEGIT_DOMAINS = [
    "paypal.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com",
    "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "coinbase.com", "binance.com", "metamask.io", "opensea.io", "paytm.com",
    "hdfcbank.com", "icicibank.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "nytimes.com", "bbc.com", "reddit.com", "spotify.com",
    "airbnb.com", "uber.com", "doordash.com", "notion.so", "slack.com",
    "zoom.us", "salesforce.com", "shopify.com", "stripe.com", "wordpress.com",
    "medium.com", "quora.com", "yelp.com", "indeed.com", "glassdoor.com",
    "coursera.org", "udemy.com", "khanacademy.org", "nasa.gov", "irs.gov",
    "weather.com", "espn.com", "cnn.com", "nasdaq.com", "investopedia.com",
    # Generic small-business / newer-brand style domains — NOT famous, NOT
    # typosquats of anything, just ordinary two-word .com names. Without
    # these, the model only ever sees "legitimate" attached to famous
    # 50-domain allowlist names, so anything unfamiliar (which describes
    # the vast majority of real small businesses and new shops) looks
    # statistically more like the phishing class than the legitimate one.
    "meridianhouse.com", "oakfieldgoods.com", "lumenworks.com",
    "brightpathstudio.com", "cedarlanemarket.com", "ironwoodcrafts.com",
    "willowcreekdesign.com", "summitridgeoutfitters.com", "harborviewco.com",
    "northfieldsupply.com", "rivertownmercantile.com", "stonebridgehome.com",
    "maplewoodkitchen.com", "graniteridgefitness.com", "clearwaterconsulting.com",
    "fernhollowfarms.com", "brassanchortravel.com", "copperleafbakery.com",
    "sandstonelegal.com", "timberlinerealty.com",
]

LEGIT_PATHS = [
    "/", "/home", "/about", "/products", "/blog/2026/06/article-title",
    "/search?q=test", "/user/profile", "/settings", "/help/faq",
    "/docs/api/v2/reference", "/pricing", "/careers", "/contact",
    "/account/dashboard", "/cart/checkout", "/news/latest",
    "/article/12345-some-title-here", "/category/electronics",
    "/watch?v=abc123", "/r/programming/comments/xyz", "/topic/python",
    # Legitimate auth/login flows — real sites have these too. Without
    # examples like this, the model learns "login keyword = phishing",
    # which produces false positives on totally normal sign-in pages.
    "/login", "/signin", "/account/login", "/auth/signin",
    "/account/security/verify", "/login?continue=/dashboard",
    "/signin/v2/identifier", "/account/recover", "/password/reset",
    "/auth/confirm-email", "/account/update-billing",
]

LEGIT_AUTH_DOMAINS = [
    "accounts.google.com", "login.microsoftonline.com", "appleid.apple.com",
    "www.facebook.com", "github.com", "id.atlassian.com", "auth0.com",
    "login.live.com", "signin.aws.amazon.com", "secure.bankofamerica.com",
    "online.chase.com", "ibanking.hdfcbank.com", "login.yahoo.com",
    "accounts.binance.com", "auth.coinbase.com",
]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
                    "loan", "work", "date", "review", "stream", "win"]

PHISHING_KEYWORDS = ["login", "signin", "verify", "secure", "account",
                      "update", "confirm", "support", "suspended", "urgent",
                      "alert", "recover", "validate", "reactivate", "wallet",
                      "claim", "billing", "payment"]

HOMOGLYPH_SUBS = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5"}


def _typosquat(brand: str) -> str:
    """Apply a random typosquatting technique to a brand name."""
    technique = random.choice(["homoglyph", "hyphen_insert", "char_swap", "char_omit", "char_add"])
    b = list(brand)

    if technique == "homoglyph":
        idx = random.randrange(len(b))
        if b[idx] in HOMOGLYPH_SUBS:
            b[idx] = HOMOGLYPH_SUBS[b[idx]]
        return "".join(b)
    elif technique == "hyphen_insert":
        idx = random.randrange(1, len(b))
        b.insert(idx, "-")
        return "".join(b)
    elif technique == "char_swap" and len(b) > 2:
        idx = random.randrange(len(b) - 1)
        b[idx], b[idx + 1] = b[idx + 1], b[idx]
        return "".join(b)
    elif technique == "char_omit" and len(b) > 3:
        idx = random.randrange(len(b))
        del b[idx]
        return "".join(b)
    else:  # char_add
        idx = random.randrange(len(b))
        b.insert(idx, random.choice("xqz"))
        return "".join(b)


def _random_token(length: int) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))


def generate_phishing_url() -> str:
    """Construct a URL following a real phishing campaign pattern."""
    pattern = random.choice([
        "typosquat_tld", "brand_subdomain", "ip_host", "keyword_stuffed",
        "long_random_subdomain", "brand_hyphen_suffix", "url_shortener_style",
    ])

    scheme = random.choice(["http", "http", "https"])  # phishing skews HTTP
    brand = random.choice(BRANDS)

    if pattern == "typosquat_tld":
        domain = _typosquat(brand)
        tld = random.choice(SUSPICIOUS_TLDS + ["com", "net"])
        kw = random.choice(PHISHING_KEYWORDS)
        return f"{scheme}://{domain}-{kw}.{tld}/{random.choice(PHISHING_KEYWORDS)}"

    elif pattern == "brand_subdomain":
        kw = random.choice(PHISHING_KEYWORDS)
        rand_domain = _random_token(random.randint(6, 14))
        tld = random.choice(SUSPICIOUS_TLDS + ["com"])
        return f"{scheme}://{brand}.{kw}.{rand_domain}.{tld}/index.php"

    elif pattern == "ip_host":
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        kw = random.choice(PHISHING_KEYWORDS)
        return f"{scheme}://{ip}/{brand}/{kw}.html"

    elif pattern == "keyword_stuffed":
        kws = random.sample(PHISHING_KEYWORDS, k=min(4, len(PHISHING_KEYWORDS)))
        domain = _random_token(random.randint(8, 16))
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"{scheme}://{domain}.{tld}/{'-'.join(kws)}"

    elif pattern == "long_random_subdomain":
        sub = _random_token(random.randint(15, 25))
        tld = random.choice(SUSPICIOUS_TLDS + ["com"])
        return f"{scheme}://{sub}.{brand}-verify.{tld}/secure/{_random_token(8)}"

    elif pattern == "brand_hyphen_suffix":
        suffix = random.choice(["security", "alert", "update", "verify", "support", "account"])
        tld = random.choice(SUSPICIOUS_TLDS + ["com", "net", "info"])
        return f"{scheme}://{brand}-{suffix}-{_random_token(4)}.{tld}/login"

    else:  # url_shortener_style with redirect param
        domain = _random_token(random.randint(5, 8))
        tld = random.choice(SUSPICIOUS_TLDS + ["com"])
        target = f"{brand}.com-{_random_token(6)}"
        return f"{scheme}://{domain}.{tld}/r?url={target}&redirect=1"


def generate_legitimate_url() -> str:
    """Construct a URL following a real legitimate-site pattern."""
    domain = random.choice(LEGIT_DOMAINS)

    # Real browsing traffic is dominated by bare homepage visits and short
    # paths — heavily weighting toward these (instead of uniformly sampling
    # all paths including long article slugs) prevents the model from
    # learning a spurious "short path = phishing" correlation. This fixes
    # a real bug found during testing: the original distribution caused
    # https://google.com/ (bare root path) to score 76% phishing, because
    # short/bare paths were underrepresented in the legitimate class
    # relative to how often they actually occur in real browsing.
    r = random.random()
    if r < 0.40:
        path = "/"
    elif r < 0.55:
        path = random.choice(["/home", "/about", "/products", "/pricing", "/contact"])
    else:
        path = random.choice(LEGIT_PATHS)

    scheme = "https"  # legit sites overwhelmingly use HTTPS

    # Occasionally add realistic subdomain (www, app, api, docs)
    if random.random() < 0.3:
        sub = random.choice(["www", "app", "api", "docs", "blog", "support", "m"])
        domain = f"{sub}.{domain}"

    url = f"{scheme}://{domain}{path}"

    # Inject realistic "hard case" noise so the model can't just memorize
    # clean templates — some legitimate sites DO have query strings,
    # numbers, even occasional hyphens (e.g. multi-word blog slugs).
    # Only applied to non-bare paths so bare-root homepages stay common
    # and clean, matching real traffic.
    if path != "/":
        r2 = random.random()
        if r2 < 0.15:
            url += f"?ref={_random_token(6)}&utm_source=newsletter"
        elif r2 < 0.25:
            url += f"-{random.randint(2020, 2026)}"
        elif r2 < 0.30:
            url = url.replace("https://", f"https://campaign-{_random_token(5)}.")

    return url


def generate_legitimate_auth_url() -> str:
    """
    Real login/signin/account-recovery pages on real, trusted domains.
    This is the critical counterexample class: without it, the model
    learns "login keyword present => phishing", which produces false
    positives on completely normal authentication flows (the most
    security-sensitive pages a user visits, ironically).
    """
    domain = random.choice(LEGIT_AUTH_DOMAINS)
    path = random.choice([
        "/login", "/signin", "/v2/identifier", "/account/login",
        "/auth/signin", "/account/security/verify",
        "/login?continue=https%3A%2F%2Fmail.google.com",
        "/signin/oauth?client_id=12345", "/account/recover",
        "/password/reset", "/auth/confirm-email",
    ])
    # Add varied query params so the combinatorial space is large enough
    # to generate thousands of unique URLs without exhausting the
    # domain x path space (15 domains x 11 paths = only 165 combos).
    if random.random() < 0.6:
        sep = "&" if "?" in path else "?"
        path += f"{sep}session={_random_token(10)}"
    return f"https://{domain}{path}"


def generate_hard_negative_phishing_url() -> str:
    """
    Phishing URLs that deliberately mimic legitimate patterns more closely
    — HTTPS (many modern phishing kits use free certs), no suspicious TLD,
    just a convincing typosquat. These are the genuinely hard cases and
    teach the model not to rely solely on "http + bad tld" shortcuts.
    """
    brand = random.choice(BRANDS)
    domain = _typosquat(brand)
    tld = random.choice(["com", "net", "org", "co"])
    path = random.choice(["/login", "/signin", "/account/verify", "/secure/update", "/"])
    return f"https://{domain}.{tld}{path}"


def _fill_class(target_count: int, generator_fn, label: int, seen: set, urls: list, labels: list, max_attempts_multiplier: int = 50):
    """
    Generate up to target_count unique URLs using generator_fn, with a hard
    attempt cap so a small combinatorial space can never cause an infinite
    loop — it just yields fewer (but still many) unique examples instead.
    """
    count = 0
    attempts = 0
    max_attempts = target_count * max_attempts_multiplier
    while count < target_count and attempts < max_attempts:
        attempts += 1
        u = generator_fn()
        if u in seen:
            continue
        seen.add(u)
        urls.append(u)
        labels.append(label)
        count += 1
    return count


def generate_dataset(n_per_class: int = 2000) -> tuple[list[str], list[int]]:
    """
    Returns (urls, labels) where label 1 = phishing, 0 = legitimate.
    Balanced dataset by default.
      - ~20% of the phishing class are "hard negatives" that mimic
        legitimate URL conventions (HTTPS, clean TLD) to prevent the
        model from learning superficial shortcuts like "http = phishing".
      - ~25% of the legitimate class are real login/auth pages, so the
        model learns that "login"/"verify"/"account" keywords alone are
        NOT phishing signal — only meaningful combined with other risk
        signals (suspicious TLD, typosquatting, IP host, etc).
    """
    urls: list[str] = []
    labels: list[int] = []
    seen: set[str] = set()

    n_hard = int(n_per_class * 0.2)
    n_easy = n_per_class - n_hard
    n_auth = int(n_per_class * 0.25)
    n_legit_general = n_per_class - n_auth

    _fill_class(n_easy, generate_phishing_url, 1, seen, urls, labels)
    _fill_class(n_hard, generate_hard_negative_phishing_url, 1, seen, urls, labels)
    _fill_class(n_auth, generate_legitimate_auth_url, 0, seen, urls, labels)
    _fill_class(n_legit_general, generate_legitimate_url, 0, seen, urls, labels)

    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


if __name__ == "__main__":
    urls, labels = generate_dataset(n_per_class=2000)
    print(f"Generated {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
    print("\nSample phishing URLs:")
    for u, l in list(zip(urls, labels))[:5]:
        if l == 1:
            print(" ", u)
    print("\nSample legitimate URLs:")
    for u, l in list(zip(urls, labels))[:20]:
        if l == 0:
            print(" ", u)
