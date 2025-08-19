import os
import sys
import yaml
import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Define file paths and constants
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_YAML = os.path.join(BASE_DIR, 'google.yaml')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# Browser User-Agent list for request headers
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Ensure googlesearch-python and ip_geolocation are installed
try:
    from googlesearch import search as google_search_lib
    from ip_geolocation import GeoLite2Country
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all dependencies are installed: pip install googlesearch-python beautifulsoup4 PyYAML requests geoip2")
    sys.exit(1)

def perform_google_search(queries, num_results=20):
    """
    Performs Google search and extracts URLs from the results.
    """
    found_links = set()
    for query in queries:
        print(f"Executing search query: {query}")
        try:
            # Corrected: Removed the 'stop' argument.
            # Using num_results for both result count and stopping.
            for url in google_search_lib(query, num_results=num_results):
                if 'github.com' not in url and 'gitlab.com' not in url and not url.startswith('http://webcache.'):
                    found_links.add(url)
            time.sleep(random.uniform(2, 5)) # Add a random delay to avoid being blocked
        except Exception as e:
            print(f"Search query '{query}' failed: {e}")
    return list(found_links)

def fetch_and_parse_yaml(url):
    """
    Attempts to download and parse YAML content from a URL.
    If the URL is a directory, it parses the HTML to find YAML links.
    """
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    nodes = []

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        try:
            data = yaml.safe_load(response.text)
            if isinstance(data, dict) and 'proxies' in data:
                nodes.extend(data['proxies'])
        except yaml.YAMLError:
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if href.endswith(('.yaml', '.yml')):
                        full_url = urljoin(url, href)
                        nodes.extend(fetch_and_parse_yaml(full_url))
            else:
                pass
    except requests.exceptions.RequestException as e:
        print(f"Processing {url} failed: {e}")
    
    return nodes

def process_links(links):
    """Uses multithreading to process all links and get proxy nodes."""
    all_nodes = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_parse_yaml, link): link for link in links}
        for future in futures:
            try:
                nodes = future.result()
                if nodes:
                    all_nodes.extend(nodes)
            except Exception as e:
                print(f"Failed to process link: {e}")
    return all_nodes

def geo_process_nodes(nodes):
    """De-duplicates nodes and names them with geolocation."""
    unique_nodes = []
    names_count = {}
    
    with GeoLite2Country(GEOLITE_DB) as geo:
        for node in nodes:
            try:
                if 'server' in node:
                    country = geo.get_country_by_ip(node['server'])
                    if country:
                        name = f"{country}_{node.get('type')}"
                        if name in names_count:
                            names_count[name] += 1
                            node['name'] = f"{name}_{names_count[name]:02d}"
                        else:
                            names_count[name] = 1
                            node['name'] = name
            except Exception as e:
                print(f"Geolocation parsing failed: {e}")
            
            if node not in unique_nodes:
                unique_nodes.append(node)
                
    return unique_nodes

def save_to_yaml(nodes, filename):
    """Saves the nodes to a YAML file."""
    final_data = {'proxies': nodes}
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True, default_flow_style=False)
    print(f"Saved {len(nodes)} unique nodes to {filename}")

if __name__ == "__main__":
    search_queries = [
        'intitle:"Index of /" "config.yaml" -github -gitlab',
        'inurl:clash "all.yaml" intext:"proxies" -github -gitlab'
    ]
    
    if not os.path.exists(GEOLITE_DB):
        print("Error: GeoLite2-Country.mmdb database not found. Please place it in the root directory of your repository.")
        sys.exit(1)

    discovered_links = perform_google_search(search_queries, num_results=50)
    
    if discovered_links:
        all_nodes = process_links(discovered_links)
        
        if all_nodes:
            unique_nodes = geo_process_nodes(all_nodes)
            save_to_yaml(unique_nodes, OUTPUT_YAML)
        else:
            print("No proxy nodes found from discovered links.")
    else:
        print("No potential links found.")
