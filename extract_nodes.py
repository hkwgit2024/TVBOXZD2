import aiohttp
import asyncio
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

# --- Utility Functions ---

async def load_known_invalid_urls():
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
# This helps filter out random text that might be falsely identified as Base64.
# Example: "Zm9vYmFyCg==" (foobar) is valid. "Zm9v" (foo) is valid.
base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?:[A-Za-z0-9+/]{16,})', re.MULTILINE)

# --- Irrelevant File Extensions ---
# Files with these extensions are typically not proxy configurations and can be skipped
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
    """
    if url in known_invalid_urls:
        debug_logs.append(f"Skipping known invalid URL: {url}")
        return False

    file_extension = os.path.splitext(url)[1].lower()
    # Explicitly allow .txt files as some configs are stored there
    if file_extension in irrelevant_extensions and file_extension != '.txt':
        debug_logs.append(f"Skipping irrelevant file extension: {url} ({file_extension})")
        return False

    # Convert GitHub's 'html_url' to 'raw.githubusercontent.com' URL for direct content access
    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with session.get(raw_url, headers=headers, timeout=20) as response:
            response.raise_for_status() # Raises an exception for 4XX/5XX HTTP responses
            content = await response.text()
            content = content[:1000000] # Limit content size to 1MB to prevent excessive memory usage

            # 1. Search for cleartext protocols (e.g., vless://, ss://)
            if protocol_pattern.search(content):
                debug_logs.append(f"Found cleartext protocol in: {url}")
                return True

            # 2. Search for Base64 encoded protocols or JSON configurations
            base64_matches = base64_pattern.findall(content)
            for b64_str in base64_matches:
                try:
                    # Attempt Base64 decode
                    # errors='ignore' handles cases where decoded string is not entirely valid UTF-8
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                    
                    # Check if decoded content contains a protocol pattern
                    if protocol_pattern.search(decoded):
                        debug_logs.append(f"Found Base64 decoded protocol in: {url}")
                        return True
                    
                    # Try to parse decoded content as JSON (e.g., for VMess configs often base64-encoded)
                    try:
                        json_data = json.loads(decoded)
                        # Check if it looks like a proxy configuration JSON (common keys for VMess, etc.)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                            debug_logs.append(f"Found Base64 JSON proxy config in: {url}")
                            return True
                    except json.JSONDecodeError:
                        pass # Not a JSON, continue to next Base64 string
                except (base64.binascii.Error, UnicodeDecodeError):
                    # Not a valid Base64 string or decoding failed, continue to next match
                    continue

            # 3. Search for YAML/JSON proxy configurations
            # Consider specific extensions or if no extension, try parsing
            if file_extension in {'.yaml', '.yml', '.conf', '.json'} or not file_extension:
                try:
                    # Try YAML parsing first (YAML is a superset of JSON, so it can parse most JSON as well)
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        # Look for common keys where proxy configurations might be stored (e.g., Clash configs)
                        for key in ['proxies', 'proxy', 'nodes', 'servers', 'outbounds']:
                            if key in yaml_data:
                                proxies_config = yaml_data[key]
                                if isinstance(proxies_config, list):
                                    for proxy in proxies_config:
                                        # Check if dictionary contains common proxy configuration keys
                                        if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                            debug_logs.append(f"Found YAML/JSON proxy list config in: {url}")
                                            return True
                                elif isinstance(proxies_config, dict): # Handle a single proxy object at the top level
                                    if any(k in proxies_config for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        debug_logs.append(f"Found YAML/JSON single proxy config in: {url}")
                                        return True
                except (yaml.YAMLError, json.JSONDecodeError): # Catch both YAML and JSON parsing errors
                    pass # Not a valid YAML/JSON, return False at the end of function

            debug_logs.append(f"No target protocol or valid configuration found in: {url}")
            return False

    except aiohttp.ClientError as e:
        debug_logs.append(f"Failed to fetch content for {url} (Network/HTTP error): {e}")
        return False
    except asyncio.TimeoutError:
        debug_logs.append(f"Timeout while fetching content for {url}.")
        return False
    except Exception as e:
        debug_logs.append(f"An unknown error occurred while verifying {url}: {e}")
        return False

async def search_and_process(session: aiohttp.ClientSession, term: str, max_pages: int, max_urls_to_find: int, known_invalid_urls: set, found_urls_set: set):
    """
    Searches GitHub for code matching a specific term, verifies found URLs,
    and collects valid ones until `max_urls_to_find` is reached or all pages are processed.
    """
    page = 1
    current_search_count = 0

    while page <= max_pages:
        # Check rate limit before each API call to avoid hitting limits
        remaining_requests = await check_rate_limit(session)
        if remaining_requests < 20 and GITHUB_TOKEN: # Proactively wait if requests are getting low
            debug_logs.append(f"Rate limit approaching ({remaining_requests} left). Waiting for reset...")
            # Re-check rate limit to get the most accurate reset time
            reset_time_response = await session.get("https://api.github.com/rate_limit", headers=headers)
            reset_data = await reset_time_response.json()
            reset_timestamp = reset_data['rate']['reset']
            wait_time = max(0, reset_timestamp - int(time.time())) + 10 # Add a 10-second buffer
            debug_logs.append(f"Waiting {wait_time} seconds before next request.")
            await asyncio.sleep(wait_time)
            # After waiting, re-check to ensure the rate limit has reset sufficiently
            remaining_requests = await check_rate_limit(session)
            if remaining_requests < 20 and GITHUB_TOKEN:
                debug_logs.append("Rate limit did not reset as expected or still too low. Aborting current search term.")
                break # Exit current search term if rate limit remains low

        params = {
            "q": quote(term, safe=''), # URL-encode the search term
            "per_page": 100, # Max items per page allowed by GitHub API
            "page": page
        }
        debug_logs.append(f"Searching for '{term}' (page {page})...")

        try:
            async with session.get(SEARCH_API_URL, headers=headers, params=params, timeout=20) as response:
                response.raise_for_status() # Raises an exception for HTTP errors
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

        if not items: # No more results for this search term or page
            break

        # Prepare verification tasks for unique URLs not yet processed in this run
        urls_to_verify = []
        for item in items:
            html_url = item["html_url"]
            # Skip common irrelevant repositories or files (e.g., GFW lists often have many false positives)
            if any(ext in html_url.lower() for ext in ['gfwlist', 'proxygfw', 'gfw.txt', 'gfw.pac']):
                debug_logs.append(f"Skipping irrelevant content: {html_url}")
                continue
            # Check against known_invalid_urls and already found URLs in the current run
            if html_url in known_invalid_urls or f"{html_url}|" in "|".join(found_urls_set):
                debug_logs.append(f"Skipping already processed or known invalid URL: {html_url}")
                continue
            urls_to_verify.append(html_url)

        # Concurrently verify the content of new URLs to improve efficiency
        verification_tasks = [verify_content(session, url, known_invalid_urls) for url in urls_to_verify]
        # `return_exceptions=True` allows gathering results even if some tasks raise exceptions
        verification_results = await asyncio.gather(*verification_tasks, return_exceptions=True)

        for i, result in enumerate(verification_results):
            original_url = urls_to_verify[i]
            if result is True: # URL passed verification
                # Store URL with UTC timestamp for traceability
                found_urls_set.add(f"{original_url}|{datetime.now(timezone.utc).isoformat()}")
                current_search_count += 1
                debug_logs.append(f"Valid URL found: {original_url} (Total found: {current_search_count})")
            elif isinstance(result, Exception): # Verification failed with an exception
                debug_logs.append(f"Verification of {original_url} failed with exception: {result}")
            else: # Verification explicitly returned False
                debug_logs.append(f"URL {original_url} did not pass verification.")

            if current_search_count >= max_urls_to_find:
                debug_logs.append(f"Reached target of {max_urls_to_find} URLs. Stopping search.")
                return # Exit the function once the target is reached

        page += 1
        # Add a small delay between pages to avoid hitting rate limits too fast
        # 2 seconds with token, 5 seconds without (lower rate limit for unauthenticated requests)
        await asyncio.sleep(2 if GITHUB_TOKEN else 5)

    debug_logs.append(f"Search for '{term}' completed for all pages or no more results.")

# --- Main Execution ---

async def main():
    """Main function to orchestrate the URL search and verification process."""
    async with aiohttp.ClientSession() as session:
        # Load known invalid URLs to skip reprocessing
        known_invalid_urls = await load_known_invalid_urls()
        found_urls_set = set() # Use a set to automatically handle duplicates and maintain uniqueness

        # Check initial API rate limit before starting extensive searches
        initial_rate_limit = await check_rate_limit(session)
        if initial_rate_limit == 0 and GITHUB_TOKEN:
            debug_logs.append("Initial rate limit is 0. Cannot proceed with search.")
            return

        # Define the target number of valid URLs to find and max pages per search term
        max_urls_to_find = 200  # <--- Adjust this value to set your desired number of URLs
        max_pages_per_term = 5 # Limit: search 5 pages per search term

        # Iterate through each search term
        for term in search_terms:
            await search_and_process(session, term, max_pages_per_term, max_urls_to_find, known_invalid_urls, found_urls_set)
            # If the global target of URLs is reached, stop all further searches
            if len(found_urls_set) >= max_urls_to_find:
                debug_logs.append(f"Global target of {max_urls_to_find} URLs reached. Stopping all searches.")
                break

        # Save unique found URLs to the output file
        found_urls_list = sorted(list(found_urls_set)) # Sort for consistent output
        with open(output_file, "w", encoding="utf-8") as f:
            for url_entry in found_urls_list:
                f.write(url_entry + "\n")
        debug_logs.append(f"Found {len(found_urls_list)} URLs, saved to {output_file}")
        print(f"Found {len(found_urls_list)} URLs, saved to {output_file}")

        # Save all debug logs to a separate file
        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"Debug logs saved to {debug_log_file}")

if __name__ == "__main__":
    # Run the main asynchronous function
    asyncio.run(main())
