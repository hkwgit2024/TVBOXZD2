import requests
import yaml
import os

# URLs of the files to download
FILE_URLS = {
    'all_unique_nodes': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt',
    'merged_configs': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt',
    'ha_link': 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml',
    'vt_link': 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml'
}

# Output file
OUTPUT_FILE = "main.yaml"

def download_file(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return None

def load_yaml_content(content):
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError:
        # If not valid YAML, return as plain text
        return content

def merge_files():
    merged_data = {}
    
    # Download and process each file
    for key, url in FILE_URLS.items():
        content = download_file(url)
        if content is None:
            print(f"Skipping {key} due to download failure")
            continue
        
        # Try to parse YAML for link.yaml files
        if 'link' in key:
            content = load_yaml_content(content)
        else:
            # Store text files as strings
            content = content.strip()
        
        merged_data[key] = content

    # Write merged data to main.yaml
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
            yaml.safe_dump(merged_data, file, allow_unicode=True, sort_keys=False)
            print(f"Successfully created {OUTPUT_FILE}")
    except Exception as e:
        print(f"Error writing to {OUTPUT_FILE}: {e}")
        exit(1)

if __name__ == "__main__":
    merge_files()
