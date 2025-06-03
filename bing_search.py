import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urldefrag

def search_bing(query):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    url = f"https://www.bing.com/search?q={query}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_urls(html_content, base_url="https://www.bing.com"):
    if not html_content:
        return set()
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith(('http://', 'https://')):
            clean_url, _ = urldefrag(href)
            urls.add(clean_url)
    return urls

def save_urls(urls, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for url in sorted(urls):
            f.write(url + '\n')

def main():
    queries = ['加速器', '机场']
    all_urls = set()
    
    for query in queries:
        print(f"Searching for: {query}")
        html = search_bing(query)
        if html:
            urls = extract_urls(html)
            all_urls.update(urls)
    
    output_file = 'data/bing.txt'
    save_urls(all_urls, output_file)
    print(f"Saved {len(all_urls)} unique URLs to {output_file}")

if __name__ == "__main__":
    main()
