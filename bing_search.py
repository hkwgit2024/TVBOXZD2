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
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
    ]
    return random.choice(user_agents)

def search_bing(query, page=1):
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'DNT': '1',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1'
    }
    url = f"https://www.bing.com/search?q={query}&first={(page-1)*10}&mkt=zh-CN&setlang=zh-CN&form=QBLH"
    logging.info(f"Requesting URL: {url} with headers: {headers['User-Agent']}")
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        is_mobile = 'mobile' in response.text.lower() or 'm.bing.com' in response.url
        logging.info(f"Page {page} for query '{query}' is {'mobile' if is_mobile else 'desktop'}")
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
            'https://support.microsoft.com/',
            'https://bingapp.microsoft.com/',
            'https://www.microsoft.com/',
            'https://www.bing.com/',
            'https://account.bing.com/',
            'https://login.live.com/'
        ]
        # 提取搜索结果链接
        for result in soup.find_all(['li', 'div'], class_=['b_algo', 'b_algoGroup', 'b_result', 'b_pag']):
            link = result.find('a', href=True)
            if link:
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    clean_url, _ = urldefrag(href)
                    if not any(clean_url.startswith(domain) for domain in exclude_domains):
                        urls.add(clean_url)
                        logging.info(f"Extracted URL: {clean_url}")
        if not urls:
            has_b_algo = bool(soup.find(['li', 'div'], class_=['b_algo', 'b_algoGroup', 'b_result']))
            logging.warning(f"No URLs extracted. Relevant selectors found: {has_b_algo}")
            # 保存部分 HTML 调试
            results_area = soup.find('ol', id='b_results')
            if results_area:
                logging.debug(f"Results area HTML: {str(results_area)[:500]}...")
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
    MAX_PAGES = 1  # 只抓取第一页

    for query in queries:
        for page in range(1, MAX_PAGES + 1):
            logging.info(f"Processing query: {query}, Page: {page}")
            html = search_bing(query, page)
            if html:
                urls = extract_urls(html)
                all_urls.update(urls)
            else:
                logging.warning(f"No content returned for {query}, page {page}")
            delay = random.uniform(2, 4)
            logging.info(f"Sleeping for {delay:.2f} seconds")
            time.sleep(delay)
    
    output_file = 'data/bing.txt'
    save_urls(all_urls, output_file)

if __name__ == "__main__":
    main()
