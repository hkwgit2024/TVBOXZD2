
import requests
import os
from bs4 import BeautifulSoup
import json
import csv
from datetime import datetime
import re

def ensure_data_directory():
    # Creating data directory if it doesn't exist
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    return data_dir

def check_url_availability(url):
    # Checking if a URL is accessible
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False

def fetch_mirror_urls_from_web():
    # Define multiple target URLs for mirror sites
    target_urls = [
        "https://jia110.github.io/",  # GitHub mirror collection
        "https://mirrors.tuna.tsinghua.edu.cn/",  # Tsinghua mirror list
        "https://mirrors.ustc.edu.cn/",  # USTC mirror list
        "https://mirrorz.org/list"  # Mirrorz.org for comprehensive mirror lists
    ]
    
    mirrors = {
        "GitHub": [],
        "Wikipedia": [],
        "Google": []
    }

    for url in target_urls:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if not href.startswith("http"):
                    href = requests.compat.urljoin(url, href)
                
                if "github" in href.lower() and href not in [m["url"] for m in mirrors["GitHub"]]:
                    mirrors["GitHub"].append({"url": href, "available": check_url_availability(href)})
                elif "wikipedia" in href.lower() and href not in [m["url"] for m in mirrors["Wikipedia"]]:
                    mirrors["Wikipedia"].append({"url": href, "available": check_url_availability(href)})
                elif ("google" in href.lower() or "scholar" in href.lower()) and href not in [m["url"] for m in mirrors["Google"]]:
                    mirrors["Google"].append({"url": href, "available": check_url_availability(href)})
        except requests.RequestException as e:
            print(f"Error fetching URLs from {url}: {e}")

    return mirrors

def fetch_mirror_urls_from_github():
    # Fetch mirror URLs from GitHub repositories
    github_api_url = "https://api.github.com/repos/mirrorz-org/mirrorz/contents/README.md"
    mirrors = {
        "GitHub": [],
        "Wikipedia": [],
        "Google": []
    }

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(github_api_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Decode README content (base64 encoded)
        import base64
        content = base64.b64decode(data["content"]).decode("utf-8")
        
        # Extract URLs using regex
        urls = re.findall(r'(https?://[^\s]+)', content)
        for url in urls:
            if "github" in url.lower() and url not in [m["url"] for m in mirrors["GitHub"]]:
                mirrors["GitHub"].append({"url": url, "available": check_url_availability(url)})
            elif "wikipedia" in url.lower() and url not in [m["url"] for m in mirrors["Wikipedia"]]:
                mirrors["Wikipedia"].append({"url": url, "available": check_url_availability(url)})
            elif ("google" in url.lower() or "scholar" in url.lower()) and url not in [m["url"] for m in mirrors["Google"]]:
                mirrors["Google"].append({"url": url, "available": check_url_availability(url)})
    except requests.RequestException as e:
        print(f"Error fetching GitHub repo data: {e}")

    return mirrors

def fetch_mirror_urls_from_search():
    # Simulate search engine results (replace with SerpAPI or similar if available)
    search_results = [
        "https://github.com.cnpmjs.org/",
        "https://zh.wikipedia.org/",
        "https://scholar.google.com/",
        "https://ghproxy.com/",
        "https://mirrors.tuna.tsinghua.edu.cn/github/",
    ]
    
    mirrors = {
        "GitHub": [],
        "Wikipedia": [],
        "Google": []
    }

    for url in search_results:
        if "github" in url.lower() and url not in [m["url"] for m in mirrors["GitHub"]]:
            mirrors["GitHub"].append({"url": url, "available": check_url_availability(url)})
        elif "wikipedia" in url.lower() and url not in [m["url"] for m in mirrors["Wikipedia"]]:
            mirrors["Wikipedia"].append({"url": url, "available": check_url_availability(url)})
        elif ("google" in url.lower() or "scholar" in url.lower()) and url not in [m["url"] for m in mirrors["Google"]]:
            mirrors["Google"].append({"url": url, "available": check_url_availability(url)})

    return mirrors

def merge_mirrors(*mirror_lists):
    # Merge multiple mirror lists, removing duplicates
    merged = {
        "GitHub": [],
        "Wikipedia": [],
        "Google": []
    }
    
    for mirrors in mirror_lists:
        for key in merged:
            for item in mirrors[key]:
                if item["url"] not in [m["url"] for m in merged[key]]:
                    merged[key].append(item)
    
    # Sort by URL and availability
    for key in merged:
        merged[key].sort(key=lambda x: (not x["available"], x["url"]))
    
    return merged

def save_to_file(mirrors, data_dir):
    # Generating timestamp for the output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = os.path.join(data_dir, f"mirror_urls_{timestamp}.json")
    csv_file = os.path.join(data_dir, f"mirror_urls_{timestamp}.csv")
    
    # Save JSON
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(mirrors, f, ensure_ascii=False, indent=4)
    
    # Save CSV
    with open(csv_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "URL", "Available"])  # CSV header
        for service, urls in mirrors.items():
            for item in urls:
                writer.writerow([service, item["url"], item["available"]])
    
    print(f"Mirror URLs saved to {json_file} and {csv_file}")

def main():
    # Ensure data directory exists
    data_dir = ensure_data_directory()
    
    # Fetch mirror URLs from multiple sources
    web_mirrors = fetch_mirror_urls_from_web()
    github_mirrors = fetch_mirror_urls_from_github()
    search_mirrors = fetch_mirror_urls_from_search()
    
    # Merge all mirrors
    mirrors = merge_mirrors(web_mirrors, github_mirrors, search_mirrors)
    
    # Save results to file
    save_to_file(mirrors, data_dir)

if __name__ == "__main__":
    main()
