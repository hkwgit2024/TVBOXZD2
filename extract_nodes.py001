import aiohttp
import asyncio # New: for async lock
import os
import re
import base64
import yaml
import json
import time
from urllib.parse import quote
from datetime import datetime, timezone # Import timezone for robust datetime handling

# --- Configuration ---
SEARCH_API_URL = "https://api.github.com/search/code"

# Get GitHub Personal Access Token from environment variable
# It's recommended to set this for higher API rate limits.
GITHUB_TOKEN = os.getenv("BOT")

# Broadened search terms for wider coverage
search_terms = [
    "v2ray  vmess" 
    "proxies type:",  # General YAML proxy configurations
    "server: port:",  # General server configurations
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://",  # Cleartext protocols
    "filename:*.yaml", "filename:*.yml",  # Match all YAML files
    "proxy:", "nodes:", "servers:",  # Other proxy-related keywords
]

# File paths for output
output_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
debug_log_file = "data/search_debug.log"

# --- Setup ---
# Ensure the 'data' directory exists
os.makedirs("data", exist_ok=True)
debug_logs = [] # Stores debug log messages

# --- Global Headers for GitHub API requests ---
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("Warning: BOT environment variable not found. Proceeding with unauthenticated requests (lower rate limit).")

# --- New: Lock for safe concurrent file writes to invalid_urls.txt ---
invalid_urls_write_lock = asyncio.Lock()


# --- Utility Functions ---

async def load_known_invalid_urls() -> set:
    """
    Loads a limited number of known invalid URLs from the invalid_urls_file.
    This helps to avoid re-processing URLs that have previously been determined as invalid.
    """
    known_invalid_urls = set()
    try:
        if os.path.exists(invalid_urls_file):
            with open(invalid_urls_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            max_invalid_urls_to_load = 1000 # Limit to prevent excessive memory usage
            for line in lines[-max_invalid_urls_to_load:]: # Load only the most recent ones
                url_part = line.strip().split("|")[0]
                if url_part:
                    known_invalid_urls.add(url_part)
            debug_logs.append(f"Loaded {len(known_invalid_urls)} known invalid URLs.")
    except Exception as e:
        debug_logs.append(f"Failed to load invalid URLs: {e}")
    return known_invalid_urls

async def check_rate_limit(session: aiohttp.ClientSession) -> int:
    """
    Checks the GitHub API rate limit and logs details.
    Returns the number of remaining requests.
    """
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as response:
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            rate_limit = await response.json()
            remaining = rate_limit['rate']['remaining']
            reset_time = datetime.fromtimestamp(rate_limit['rate']['reset'], tz=timezone.utc) # Use timezone-aware datetime
            debug_logs.append(f"GitHub API Rate Limit: {remaining} remaining, resets at {reset_time}.")
            return remaining
    except Exception as e:
        debug_logs.append(f"Failed to check rate limit: {e}")
        return 0 # Indicate no requests left if check fails

# --- Regex Patterns ---
# Relaxed protocol pattern to match common proxy schemes (ss, hysteria2, vless, vmess, trojan)
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>"\'`]+', re.MULTILINE | re.IGNORECASE)

# Stricter Base64 pattern: requires length to be a multiple of 4, allows padding, min length 16.
base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?:[A-Za-z0-9+/]{16,})', re.MULTILINE)

# --- Irrelevant File Extensions ---
irrelevant_extensions = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.md', '.markdown', '.rst', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dll', '.bin', '.so', '.lib',
    '.log', '.gitignore', '.editorconfig', '.gitattributes', '.iml',
    '.svg', '.xml', '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.c', '.cpp', '.h', '.hpp', '.php', '.go', '.rs', '.swift', '.kt', '.sh', '.bash', '.ps1', '.bat', '.cmd', '.rb', '.pl'
}

# --- Core Logic Functions ---

async def verify_content(session: aiohttp.ClientSession, url: str, known_invalid_urls: set) -> bool:
    """
    Fetches content from a URL and verifies if it contains proxy configurations.
    It checks for cleartext protocols, Base64 encoded protocols/JSON, and YAML/JSON configurations.
    Returns True if valid, False otherwise.
    If content is found to be invalid, logs it to invalid_urls.txt.
    """
    if url in known_invalid_urls:
        debug_logs.append(f"Skipping known invalid URL: {url}")
        return False

    file_extension = os.path.splitext(url)[1].lower()
    if file_extension in irrelevant_extensions and file_extension != '.txt':
        debug_logs.append(f"Skipping irrelevant file extension: {url} ({file_extension})")
        # Log to invalid_urls.txt as it's an irrelevant file for our purpose
        await log_invalid_url(url, "Irrelevant file type")
        return False

    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with session.get(raw_url, headers=headers, timeout=20) as response:
            response.raise_for_status()
            content = await response.text()
            content = content[:1000000] # Limit content size to 1MB

            # 1. Search for cleartext protocols (e.g., vless://, ss://)
            if protocol_pattern.search(content):
                debug_logs.append(f"Found cleartext protocol in: {url}")
                return True

            # 2. Search for Base64 encoded protocols or JSON configurations
            base64_matches = base64_pattern.findall(content)
            for b64_str in base64_matches:
                try:
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                    if protocol_pattern.search(decoded):
                        debug_logs.append(f"Found Base64 decoded protocol in: {url}")
                        return True
                    try:
                        json_data = json.loads(decoded)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id', 'proxies', 'outbounds']):
                            debug_logs.append(f"Found Base64 JSON proxy config in: {url}")
                            return True
                    except json.JSONDecodeError:
                        pass
                except (base64.binascii.Error, UnicodeDecodeError):
                    continue

            # 3. Search for YAML/JSON proxy configurations
            if file_extension in {'.yaml', '.yml', '.conf', '.json'} or not file_extension:
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        for key in ['proxies', 'proxy', 'nodes', 'servers', 'outbounds']:
                            if key in yaml_data:
                                proxies_config = yaml_data[key]
                                if (isinstance(proxies_config, list) and any(isinstance(p, dict) and any(k in p for k in ['server', 'port', 'type']) for p in proxies_config)) or \
                                   (isinstance(proxies_config, dict) and any(k in proxies_config for k in ['server', 'port', 'type'])):
                                    debug_logs.append(f"Found YAML/JSON proxy config in: {url}")
                                    return True
                except (yaml.YAMLError, json.JSONDecodeError):
                    pass

            debug_logs.append(f"No target protocol or valid configuration found in: {url}")
            await log_invalid_url(url, "No proxy configuration found") # New: Log to invalid_urls.txt
            return False

    except aiohttp.ClientError as e:
        debug_logs.append(f"Failed to fetch content for {url} (Network/HTTP error): {e}")
        await log_invalid_url(url, f"Failed to fetch content: {type(e).__name__}") # New: Log fetch errors
        return False
    except asyncio.TimeoutError:
        debug_logs.append(f"Timeout while fetching content for {url}.")
        await log_invalid_url(url, "Fetch timeout") # New: Log timeout
        return False
    except Exception as e:
        debug_logs.append(f"An unknown error occurred while verifying {url}: {e}")
        await log_invalid_url(url, f"Verification error: {type(e).__name__}") # New: Log other errors
        return False

async def log_invalid_url(url: str, reason: str):
    """Logs an invalid URL to the invalid_urls_file with a timestamp and reason."""
    async with invalid_urls_write_lock:
        try:
            with open(invalid_urls_file, "a+", encoding="utf-8") as f:
                f.seek(0) # Move to the beginning to read existing content
                existing_lines = f.readlines()
                # Check if URL (without timestamp/reason) already exists in the file
                if not any(url in line for line in existing_lines):
                    f.write(f"{url}|{datetime.now(timezone.utc).isoformat()}|{reason}\n")
                    debug_logs.append(f"Logged invalid URL to {invalid_urls_file}: {url} (Reason: {reason})")
        except Exception as e:
            debug_logs.append(f"Error logging invalid URL {url} to {invalid_urls_file}: {e}")

async def search_and_process(session: aiohttp.ClientSession, term: str, max_pages: int, max_urls_to_find: int, known_invalid_urls: set, found_urls_set: set):
    """
    Searches GitHub for code matching a specific term, verifies found URLs,
    and collects valid ones until `max_urls_to_find` is reached or all pages are processed.
    """
    page = 1
    current_search_count = 0

    while page <= max_pages:
        remaining_requests = await check_rate_limit(session)
        if remaining_requests < 20 and GITHUB_TOKEN:
            debug_logs.append(f"Rate limit approaching ({remaining_requests} left). Waiting for reset...")
            reset_time_response = await session.get("https://api.github.com/rate_limit", headers=headers)
            reset_data = await reset_time_response.json()
            reset_timestamp = reset_data['rate']['reset']
            wait_time = max(0, reset_timestamp - int(time.time())) + 10
            debug_logs.append(f"Waiting {wait_time} seconds before next request.")
            await asyncio.sleep(wait_time)
            remaining_requests = await check_rate_limit(session)
            if remaining_requests < 20 and GITHUB_TOKEN:
                debug_logs.append("Rate limit did not reset as expected or still too low. Aborting current search term.")
                break

        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        debug_logs.append(f"Searching for '{term}' (page {page})...")

        try:
            async with session.get(SEARCH_API_URL, headers=headers, params=params, timeout=20) as response:
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError as e:
            debug_logs.append(f"Search for '{term}' (page {page}) failed (Network/HTTP error): {e}")
            break
        except asyncio.TimeoutError:
            debug_logs.append(f"Search for '{term}' (page {page}) timed out.")
            break
        except Exception as e:
            debug_logs.append(f"An error occurred during search for '{term}' (page {page}): {e}")
            break

        items = data.get("items", [])
        debug_logs.append(f"Found {len(items)} results for '{term}' (page {page}).")

        if not items:
            break

        urls_to_verify = []
        for item in items:
            html_url = item["html_url"]
            if any(ext in html_url.lower() for ext in ['gfwlist', 'proxygfw', 'gfw.txt', 'gfw.pac']):
                debug_logs.append(f"Skipping irrelevant content: {html_url}")
                await log_invalid_url(html_url, "Irrelevant content (keyword match)") # Log skipped irrelevant URLs
                continue
            if html_url in known_invalid_urls or f"{html_url}|" in "|".join(found_urls_set):
                debug_logs.append(f"Skipping already processed or known invalid URL: {html_url}")
                continue
            urls_to_verify.append(html_url)

        verification_tasks = [verify_content(session, url, known_invalid_urls) for url in urls_to_verify]
        verification_results = await asyncio.gather(*verification_tasks, return_exceptions=True)

        for i, result in enumerate(verification_results):
            original_url = urls_to_verify[i]
            if result is True:
                found_urls_set.add(f"{original_url}|{datetime.now(timezone.utc).isoformat()}")
                current_search_count += 1
                debug_logs.append(f"Valid URL found: {original_url} (Total found: {current_search_count})")
            elif isinstance(result, Exception):
                debug_logs.append(f"Verification of {original_url} failed with exception: {result}")
                # log_invalid_url is already called inside verify_content for exceptions
            else:
                debug_logs.append(f"URL {original_url} did not pass verification.")
                # log_invalid_url is already called inside verify_content for content not found

            if current_search_count >= max_urls_to_find:
                debug_logs.append(f"Reached target of {max_urls_to_find} URLs. Stopping search.")
                return

        page += 1
        await asyncio.sleep(2 if GITHUB_TOKEN else 5)

    debug_logs.append(f"Search for '{term}' completed for all pages or no more results.")

# --- Main Execution ---

async def main():
    """Main function to orchestrate the URL search and verification process."""
    async with aiohttp.ClientSession() as session:
        known_invalid_urls = await load_known_invalid_urls()
        found_urls_set = set()

        initial_rate_limit = await check_rate_limit(session)
        if initial_rate_limit == 0 and GITHUB_TOKEN:
            debug_logs.append("Initial rate limit is 0. Cannot proceed with search.")
            return

        max_urls_to_find = 200
        max_pages_per_term = 5

        for term in search_terms:
            await search_and_process(session, term, max_pages_per_term, max_urls_to_find, known_invalid_urls, found_urls_set)
            if len(found_urls_set) >= max_urls_to_find:
                debug_logs.append(f"Global target of {max_urls_to_find} URLs reached. Stopping all searches.")
                break

        found_urls_list = sorted(list(found_urls_set))
        with open(output_file, "w", encoding="utf-8") as f:
            for url_entry in found_urls_list:
                f.write(url_entry + "\n")
        debug_logs.append(f"Found {len(found_urls_list)} URLs, saved to {output_file}")
        print(f"Found {len(found_urls_list)} URLs, saved to {output_file}")

        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"Debug logs saved to {debug_log_file}")

if __name__ == "__main__":
    asyncio.run(main())
