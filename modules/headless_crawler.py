import asyncio
import re
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Optional

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

JS_FRAMEWORK_PATTERNS = [
    # React
    r"react\.development\.js",
    r"react\.production\.min\.js",
    r"__REACT_DEVTOOLS",
    r"_reactFiber",
    r"data-reactroot",
    # Vue
    r"vue\.runtime",
    r"__vue__",
    r"data-v-",
    # Angular
    r"ng-version",
    r"angular\.min\.js",
    r"ng-app",
    # Next.js
    r"__NEXT_DATA__",
    r"_next/static",
    # Nuxt
    r"__NUXT__",
    # General SPA indicators
    r"<div id=['\"]app['\"]>",
    r"<div id=['\"]root['\"]>",
]

SENSITIVE_INPUT_TYPES = [
    "text", "email", "password", "search",
    "tel", "url", "number", "hidden",
]


# ─────────────────────────────────────────
# JS FRAMEWORK DETECTION
# ─────────────────────────────────────────

def is_js_heavy_site(html: str) -> bool:
    """
    Detect if a site uses a JS framework that needs headless rendering.
    Returns True if Playwright should be used.
    """
    for pattern in JS_FRAMEWORK_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    # Check if body has very little content (SPA shell)
    body_match = re.search(
        r"<body[^>]*>(.*?)</body>", html,
        re.DOTALL | re.IGNORECASE
    )
    if body_match:
        body_content = body_match.group(1)
        # Strip tags and check text length
        text = re.sub(r"<[^>]+>", "", body_content).strip()
        if len(text) < 100:
            return True

    return False


# ─────────────────────────────────────────
# PAGE DATA EXTRACTOR
# ─────────────────────────────────────────

def extract_page_data(html: str, url: str, base_domain: str) -> dict:
    """
    Extract links, forms, inputs, and API calls from page HTML.
    Works on both static and JS-rendered HTML.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")

    # Extract links
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(
            ("#", "mailto:", "tel:", "javascript:", "whatsapp:")
        ):
            continue
        full_url = urljoin(url, href)
        parsed   = urlparse(full_url)
        clean    = urlunparse(parsed._replace(fragment=""))
        if parsed.netloc == base_domain and parsed.scheme in ("http", "https"):
            links.append(clean)

    # Extract forms
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action", url))
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            typ  = inp.get("type", "text").lower()
            val  = inp.get("value", "")
            if name:
                inputs.append({"name": name, "type": typ, "value": val})
        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "url":    url,
            })

    # Extract API endpoints from script tags
    api_endpoints = []
    for script in soup.find_all("script"):
        content = script.string or ""
        # Find fetch/axios calls
        api_patterns = [
            r'fetch\(["\'](/[^"\']+)["\']',
            r'axios\.[a-z]+\(["\'](/[^"\']+)["\']',
            r'["\'](/api/[^"\'?\s]{2,60})["\']',
            r'url:\s*["\'](/[^"\']+)["\']',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                full = urljoin(url, match)
                if base_domain in full:
                    api_endpoints.append(full)

    return {
        "url":          url,
        "links":        list(set(links)),
        "forms":        forms,
        "api_endpoints": list(set(api_endpoints)),
    }


# ─────────────────────────────────────────
# HEADLESS CRAWLER (Playwright)
# ─────────────────────────────────────────

async def crawl_with_playwright(
    url: str,
    max_pages: int = 20,
    depth: int = 2,
    stealth: bool = False,
) -> dict:
    """
    Crawl a JS-rendered site using Playwright headless browser.
    Returns dict with pages, forms, and API endpoints found.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "pages": [url], "forms": [],
            "api_endpoints": [], "error": "Playwright not installed",
        }

    visited      = set()
    to_visit     = [url]
    all_pages    = []
    all_forms    = []
    all_apis     = []
    base_domain  = urlparse(url).netloc

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--no-first-run",
                "--no-zygote",
                "--disable-gpu",
            ]
        )

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )

        # Intercept API calls
        api_calls_intercepted = []

        async def handle_request(request):
            if any(kw in request.url for kw in
                   ["/api/", "/graphql", "/rest/",
                    ".json", "/v1/", "/v2/"]):
                parsed = urlparse(request.url)
                if parsed.netloc == base_domain:
                    api_calls_intercepted.append(request.url)

        context.on("request", handle_request)

        for current_depth in range(depth):
            next_level = []

            for page_url in to_visit[:max_pages]:
                if page_url in visited:
                    continue
                visited.add(page_url)

                try:
                    page = await context.new_page()

                    # Go to page and wait for JS to render
                    await page.goto(
                        page_url,
                        wait_until="networkidle",
                        timeout=15000,
                    )

                    # Wait a bit more for dynamic content
                    await page.wait_for_timeout(1000)

                    # Get fully rendered HTML
                    html = await page.content()

                    # Extract data
                    data = extract_page_data(html, page_url, base_domain)
                    all_pages.append({
                        "url":    page_url,
                        "title":  await page.title(),
                        "forms":  data["forms"],
                    })
                    all_forms.extend(data["forms"])
                    all_apis.extend(data["api_endpoints"])

                    # Queue new links
                    for link in data["links"]:
                        if link not in visited:
                            next_level.append(link)

                    await page.close()

                except Exception:
                    try:
                        await page.close()
                    except Exception:
                        pass
                    continue

            to_visit = next_level[:30]

        await browser.close()

    # Add intercepted API calls
    all_apis.extend(api_calls_intercepted)

    return {
        "pages":         all_pages,
        "forms":         all_forms,
        "api_endpoints": list(set(all_apis)),
        "error":         None,
    }


# ─────────────────────────────────────────
# SMART CRAWLER — auto picks best method
# ─────────────────────────────────────────

def smart_crawl(
    url: str,
    max_pages: int = 20,
    depth: int = 2,
    stealth: bool = False,
    force_headless: bool = False,
) -> dict:
    """
    Auto-detects if site needs headless browser.
    Uses Playwright for JS-heavy sites, requests for static sites.
    Returns unified result dict.
    """
    import requests as req
    import urllib3
    urllib3.disable_warnings()

    result = {
        "url":          url,
        "mode":         "requests",
        "pages":        [],
        "forms":        [],
        "api_endpoints": [],
        "js_heavy":     False,
        "page_count":   0,
    }

    # First — check if site needs headless
    try:
        resp = req.get(
            url, timeout=10, verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True,
        )
        html     = resp.text
        real_url = resp.url
    except Exception as e:
        result["error"] = str(e)
        return result

    js_heavy = force_headless or is_js_heavy_site(html)
    result["js_heavy"] = js_heavy

    if js_heavy:
        # Use Playwright
        result["mode"] = "headless"
        try:
            loop        = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            headless_result = loop.run_until_complete(
                crawl_with_playwright(real_url, max_pages, depth, stealth)
            )
            loop.close()

            if not headless_result.get("error"):
                result["pages"]         = headless_result["pages"]
                result["forms"]         = headless_result["forms"]
                result["api_endpoints"] = headless_result["api_endpoints"]
                result["page_count"]    = len(headless_result["pages"])
            else:
                # Playwright failed — fall back to requests
                result["mode"]  = "requests_fallback"
                result["error"] = headless_result["error"]
                js_heavy        = False

        except Exception as e:
            result["mode"]  = "requests_fallback"
            result["error"] = str(e)
            js_heavy        = False

    if not js_heavy:
        # Use fast requests crawler
        from modules.web_scanner import crawl_links
        import requests as rq

        session = rq.Session()
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        pages = crawl_links(real_url, session, depth=depth, stealth=stealth)

        from bs4 import BeautifulSoup
        all_forms = []
        for page_url in pages[:max_pages]:
            try:
                r    = session.get(page_url, timeout=8, verify=False)
                soup = BeautifulSoup(r.text, "html.parser")
                data = extract_page_data(r.text, page_url,
                                         urlparse(url).netloc)
                all_forms.extend(data["forms"])
                result["pages"].append({
                    "url":   page_url,
                    "title": soup.title.string if soup.title else "",
                    "forms": data["forms"],
                })
            except Exception:
                continue

        result["forms"]      = all_forms
        result["page_count"] = len(result["pages"])

    return result