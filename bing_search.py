import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urldefrag
import random
import time
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_random_user_agent():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 10; SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; HarmonyOS; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 10; HUAWEI MatePad 10.8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Safari/537.36'
    ]
    return random.choice(user_agents)

def search_bing(query, page=1):
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
    }
    url = f"https://www.bing.com/search?q={query}&first={(page-1)*10}"
    logging.info(f"Requesting URL: {url} with headers: {headers['User-Agent']}")
    try:
        response = requests.get(url, headers=headers, timeout=5)  # 缩短超时时间
        response.raise_for_status()
        logging.info(f"Successfully fetched page {page} for query: {query}")
        return response.text
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return None

def extract_urls(html_content, base_url="https://www.bing.com"):
    if not html_content:
        logging.warning("No HTML content to parse")
        return set()
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        urls = set()
        exclude_domains = [
            'https://www.zhihu.com/',
            'https://jingyan.baidu.com/',
            'https://go.microsoft.com/',
            'https://support.microsoft.com/'
        ]
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('http://', 'https://')):
                clean_url, _ = urldefrag(href)
                if not any(clean_url.startswith(domain) for domain in exclude_domains):
                    urls.add(clean_url)
        logging.info(f"Extracted {len(urls)} URLs from page")
        return urls
    except Exception as e:
        logging.error(f"Error parsing HTML: {e}")
        return set()

def save_urls(urls, output_file):
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        logging.info(f"Saved {len(urls)} unique URLs to {output_file}")
    except Exception as e:
        logging.error(f"Error saving URLs to {output_file}: {e}")

def main():
    queries = ['加速器', '机场']
    all_urls = set()
    MAX_PAGES = 8  # 抓取前3页

    for query in queries:
        for page in range(1, MAX_PAGES + 1):
            logging.info(f"Processing query: {query}, Page: {page}")
            html = search_bing(query, page)
            if html:
                urls = extract_urls(html)
                all_urls.update(urls)
            else:
                logging.warning(f"No content returned for {query}, page {page}")
            # 随机延时1-3秒
            delay = random.uniform(1, 3)
            logging.info(f"Sleeping for {delay:.2f} seconds")
            time.sleep(delay)
    
    output_file = 'data/bing.txt'
    save_urls(all_urls, output_file)

if __name__ == "__main__":
    main()
