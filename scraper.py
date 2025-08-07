import requests
import json
import yaml
import os
import sys

def search_and_save_tvbox_interfaces():
    """
    Searches GitHub for TVbox interface files (JSON and YAML),
    validates them, and saves valid ones to a local 'box/' directory.
    """
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        print("GITHUB_TOKEN is not set. Exiting.")
        sys.exit(1)

    # 优化后的精准搜索查询：
    # 移除了 '饭太硬.ga'，因为它可能包含不受支持的字符。
    # 保留了文件名和文件内容中的关键英文字符。
    query = "filename:tvbox.json OR filename:tvbox.yml OR filename:alist.yml OR filename:drpy.json OR \"sites\" in:file OR \"spider\" in:file"
    
    search_url = "https://api.github.com/search/code"
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.raw"
    }
    
    if not os.path.exists("box"):
        os.makedirs("box")
    
    try:
        print(f"Searching GitHub for files with query: \"{query}\"...")
        response = requests.get(search_url, params={"q": query, "per_page": 50}, headers=headers)
        response.raise_for_status()
        
        search_results = response.json()
        print(f"Found {len(search_results['items'])} potential interface files.")
        
        for item in search_results["items"]:
            file_name = item["path"].split("/")[-1]
            repo_full_name = item['repository']['full_name']
            
            # 过滤掉一些已知的不相关文件
            if 'config.yml' in file_name.lower() and ('-sdk' in repo_full_name or 'actions' in repo_full_name):
                continue

            print(f"\n--- Processing {file_name} from {repo_full_name} ---")
            
            raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            print(f"Fetching raw content from: {raw_url}")
            
            file_content = requests.get(raw_url)
            
            is_valid = False
            content_type = "unknown"
            if file_name.endswith((".json", ".jsonc")):
                is_valid, content_type = validate_interface_json(file_content.text)
            elif file_name.endswith((".yml", ".yaml")):
                is_valid, content_type = validate_interface_yaml(file_content.text)

            if is_valid:
                print(f"Validation successful! Content type: {content_type}. Saving interface...")
                
                save_path = os.path.join("box", file_name)
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(file_content.text)
                print(f"Successfully saved {file_name} to 'box/'")
            else:
                print("Validation failed. Skipping this file.")
                
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print("Error decoding JSON from search results.", file=sys.stderr)

def validate_interface_json(json_str: str) -> (bool, str):
    try:
        data = json.loads(json_str)
        if "sites" in data or "lives" in data or "spider" in data:
            return True, "JSON"
    except json.JSONDecodeError:
        pass
    return False, "invalid"

def validate_interface_yaml(yaml_str: str) -> (bool, str):
    try:
        data = yaml.safe_load(yaml_str)
        if isinstance(data, dict) and ("sites" in data or "spider" in data or "proxies" in data):
            return True, "YAML"
    except yaml.YAMLError:
        pass
    return False, "invalid"

if __name__ == "__main__":
    search_and_save_tvbox_interfaces()
