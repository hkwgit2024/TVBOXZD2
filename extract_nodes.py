import os
import re
import base64
import yaml
import json
import time
import datetime
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from github import Github
from github.GithubException import RateLimitExceededException, UnknownObjectException
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("node_extractor.log"), logging.StreamHandler()]
)

# Parse command-line arguments
parser = argparse.ArgumentParser(description="GitHub Node Extractor")
parser.add_argument("--output", default="data/clash_config.yaml", help="Output Clash config file path")
parser.add_argument("--history", default="data/nodes_history.json", help="History file path")
parser.add_argument("--config", default="config.yaml", help="Configuration file path")
args = parser.parse_args()

# Load configuration file
def load_config(config_file):
    default_config = {
        "search": {
            "extensions": ["txt", "md", "json", "yaml", "yml", "conf", "cfg"],
            "keywords": ["ss://", "ssr://", "vmess://", "trojan://", "vless://", "hysteria://"],
            "excluded_extensions": [
                "zip", "tar", "gz", "rar", "7z", "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico",
                "mp3", "wav", "ogg", "mp4", "avi", "mov", "mkv", "pdf", "doc", "docx", "xls",
                "xlsx", "ppt", "pptx", "exe", "dll", "so", "bin", "class", "jar", "pyc"
            ]
        },
        "query_delay_seconds": 38,
        "max_file_size": 1_000_000,  # 1MB
        "history_expiry_days": 30,
        "max_parallel_workers": 5
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            default_config.update(user_config)
            logging.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logging.warning(f"Failed to load config file {config_file}: {e}. Using default config.")
    return default_config

CONFIG = load_config(args.config)
HISTORY_FILE = args.history
OUTPUT_FILE = args.output

# Initialize GitHub client
GITHUB_TOKEN = os.getenv("BOT")
if not GITHUB_TOKEN:
    logging.error("GitHub token (BOT) not found. Please set the 'BOT' environment variable.")
    exit(1)
g = Github(GITHUB_TOKEN)

# Load history file
nodes_history = {}
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            nodes_history = json.load(f)
        logging.info(f"Loaded {len(nodes_history)} nodes from history: {HISTORY_FILE}")
    except json.JSONDecodeError:
        logging.warning(f"Could not decode JSON from {HISTORY_FILE}. Starting with empty history.")
        nodes_history = {}
    except Exception as e:
        logging.error(f"Failed to load history file {HISTORY_FILE}: {e}. Starting with empty history.")
        nodes_history = {}

current_run_nodes = set()

# Protocol and search keywords
protocol_keywords = CONFIG["search"]["keywords"]
search_keywords = protocol_keywords + [kw.split("://")[0] for kw in protocol_keywords if "://" in kw]
search_extensions = CONFIG["search"]["extensions"]
excluded_extensions = CONFIG["search"]["excluded_extensions"]

# Generate search queries
search_queries = []
override_query = os.getenv("OVERRIDE_SEARCH_QUERY")
if override_query:
    search_queries.append(override_query)
else:
    for ext in search_extensions:
        for kw in search_keywords:
            search_queries.append(f'"{kw}" in:file extension:{ext}')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:config')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:nodes')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:sub')
    excluded_query_part = " ".join([f"-extension:{e}" for e in excluded_extensions])
    general_nodes_query = f'({" OR ".join([f'"{kw}"' for kw in protocol_keywords])}) in:file {excluded_query_part}'
    search_queries.append(general_nodes_query)
logging.info(f"Generated {len(search_queries)} search queries.")

# Regular expression for node extraction
NODE_PATTERN = re.compile(r"(ss://[^\s]+|ssr://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|vless://[^\s]+|hysteria://[^\s]+)")

# Node extractor interface
class NodeExtractor:
    def extract(self, content):
        raise NotImplementedError

class Base64Extractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            cleaned_text = content.replace(" ", "").replace("\n", "").replace("\r", "")
            padding_needed = 4 - (len(cleaned_text) % 4)
            if padding_needed != 4:
                cleaned_text += '=' * padding_needed
            decoded_bytes = base64.b64decode(cleaned_text, validate=True)
            decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
            links.extend(NODE_PATTERN.findall(decoded_string))
        except Exception:
            pass
        return links

class YAMLExtractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, (dict, list)):
                def find_urls_in_yaml(item):
                    if isinstance(item, dict):
                        for key, value in item.items():
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, list):
                        for value in item:
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, str):
                        links.extend(NODE_PATTERN.findall(item))
                find_urls_in_yaml(data)
        except yaml.YAMLError:
            pass
        return links

extractors = [Base64Extractor(), YAMLExtractor()]

# Process a single search result
def process_search_result(result):
    global current_run_nodes
    try:
        if result.size > CONFIG["max_file_size"]:
            logging.warning(f"Skipping {result.path} in {result.repository.full_name}: File size {result.size} exceeds {CONFIG['max_file_size']} bytes.")
            return

        file_content = result.decoded_content.decode('utf-8', errors='ignore')
        found_nodes = NODE_PATTERN.findall(file_content)
        current_run_nodes.update(found_nodes)

        # Apply extractors
        for extractor in extractors:
            current_run_nodes.update(extractor.extract(file_content))

        # Process Base64 encoded content
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}(?:={0,2})")
        for b64_str in base64_pattern.findall(file_content):
            for extractor in extractors:
                if isinstance(extractor, Base64Extractor):
                    current_run_nodes.update(extractor.extract(b64_str))

        logging.debug(f"Processed {result.path} in {result.repository.full_name}: Found {len(found_nodes)} nodes.")

    except UnknownObjectException as e:
        logging.warning(f"Access denied or object not found for {result.path} in {result.repository.full_name}: {e}")
    except Exception as e:
        logging.error(f"Error processing {result.path} in {result.repository.full_name}: {e}")

# Parallel processing of search results
def process_search_results_parallel(results, max_workers):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm(executor.map(process_search_result, results), desc="Processing search results", unit="file"))

# Clean old history entries
def clean_old_nodes(history):
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=CONFIG["history_expiry_days"])
    return {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v) > cutoff}

# Generate Clash configuration
def save_as_clash_config(nodes, output_file):
    clash_config = {
        "proxies": [],
        "proxy-groups": [
            {
                "name": "auto",
                "type": "url-test",
                "proxies": [],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": [
            "MATCH,auto"
        ]
    }
    for idx, node in enumerate(sorted(nodes)):
        proxy = {
            "name": f"node-{idx}",
            "type": node.split("://")[0],
            "server": "unknown",
            "port": 0,
            "node-url": node
        }
        clash_config["proxies"].append(proxy)
        clash_config["proxy-groups"][0]["proxies"].append(f"node-{idx}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    logging.info(f"Saved Clash config with {len(nodes)} proxies to '{output_file}'")

# Main logic
def main():
    global current_run_nodes
    for current_query in search_queries:
        logging.info(f"Searching GitHub for: '{current_query}'...")
        try:
            rate_limit_before = g.get_rate_limit().core
            reset_timestamp = rate_limit_before.reset.timestamp()
            logging.info(f"Before query - Remaining API calls: {rate_limit_before.remaining}/{rate_limit_before.limit}, Resets at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}")

            search_results = g.search_code(query=current_query)
            process_search_results_parallel(search_results, CONFIG["max_parallel_workers"])
            logging.info(f"Finished processing results for query '{current_query}'")
            time.sleep(CONFIG["query_delay_seconds"])

        except RateLimitExceededException:
            logging.warning("GitHub API Rate Limit Exceeded")
            rate_limit = g.get_rate_limit().core
            reset_timestamp = rate_limit.reset.timestamp()
            wait_seconds = reset_timestamp - time.time() + 5
            reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))
            logging.info(f"Current remaining API calls: {rate_limit.remaining}. Waiting {wait_seconds} seconds until {reset_time_utc}...")
            time.sleep(max(wait_seconds, 0))
            continue
        except Exception as e:
            logging.error(f"Unexpected error during search query '{current_query}': {e}")
            continue

    # Update history
    current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    newly_added_count = 0
    for node_link in current_run_nodes:
        if node_link not in nodes_history:
            newly_added_count += 1
        nodes_history[node_link] = current_timestamp

    # Clean expired history entries
    nodes_history.update(clean_old_nodes(nodes_history))

    logging.info(f"\n--- Node History Update ---")
    logging.info(f"Found {len(current_run_nodes)} unique nodes in current run.")
    logging.info(f"Newly added nodes to history: {newly_added_count}")
    logging.info(f"Total nodes in history: {len(nodes_history)}")

    # Save history
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(nodes_history, f, ensure_ascii=False, indent=2)
        logging.info(f"Updated node history saved to '{HISTORY_FILE}'")
    except Exception as e:
        logging.error(f"Failed to save history file {HISTORY_FILE}: {e}")

    # Save Clash configuration
    save_as_clash_config(current_run_nodes, OUTPUT_FILE)

if __name__ == "__main__":
    main()
