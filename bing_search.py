import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urldefrag
import random
import time

def get_random_user_agent():
    user_agents = [
        # 电脑 (Windows PC)
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        # 电脑 (Mac)
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        # 平板 (iPad)
        'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        # 平板 (Android Tablet)
        'Mozilla/5.0 (Linux; Android 10; SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Mobile Safari/537.36',
        # 手机 (iPhone)
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
        # 手机 (Android)
        'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        # 手机 (鸿蒙 HarmonyOS)
        'Mozilla/5.0 (Linux; Android 10; HarmonyOS; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        # Pad (华为 MatePad)
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
    # Bing 分页参数：first=0（第1页）, first=10（第2页）, first=20（第3页）等
    url = f"https://www.bing.com/search?q={query}&first={(page-1)*10}"
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
    return urls

def save_urls(urls, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for url in sorted(urls):
            f.write(url + '\n')

def main():
    queries = ['加速器', '机场']
    all_urls = set()
    MAX_PAGES = 30  # 抓取前3页，可调整

    for query in queries:
        for page in range(1, MAX_PAGES + 1):
            user_agent = get_random_user_agent()
            print(f"Searching for: {query}, Page: {page}, User-Agent: {user_agent}")
            html = search_bing(query, page)
            if html:
                urls = extract_urls(html)
                all_urls.update(urls)
            # 随机延时1-3秒，模拟人工翻页
            time.sleep(random.uniform(1, 3))
    
    output_file = 'data/bing.txt'
    save_urls(all_urls, output_file)
    print(f"Saved {len(all_urls)} unique URLs to {output_file}")

if __name__ == "__main__":
    main()
