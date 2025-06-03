import requests
from bs4 import BeautifulSoup
import os
import time
import random
import base64
from urllib.parse import unquote

def extract_urls_from_bing_html(html_content):
    """
    从 Bing 搜索结果的 HTML 内容中提取 URL。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找 data-url 属性 (通常是直接的目标 URL)
    for div_tag in soup.find_all('div', class_='gs_cit'):
        data_url = div_tag.get('data-url')
        if data_url and (data_url.startswith('http://') or data_url.startswith('https://')):
            extracted_urls.add(data_url.strip())

    # 策略 2: 查找 gs_cit_siteurl 类中的文本内容
    for siteurl_div in soup.find_all('div', class_='gs_cit_siteurl'):
        url_text = siteurl_div.get_text()
        if url_text and (url_text.startswith('http://') or url_text.startswith('https://')):
            extracted_urls.add(url_text.strip())

    # 策略 3: 解析 Bing 的重定向链接 (需要 Base64 解码)
    for link in soup.find_all('a', href=True):
        href = link['href']
        if "bing.com/ck/a?" in href and "u=" in href:
            try:
                # 提取 u= 后面的 Base64 编码字符串
                u_param_start = href.find("u=") + 2
                u_param_end = href.find("&", u_param_start)
                if u_param_end == -1: # 如果 u 是最后一个参数
                    u_param_end = len(href)
                
                encoded_url = href[u_param_start:u_param_end]
                
                # Bing 的 Base64 编码通常前面会有一个 'a1' 或类似的前缀，需要移除
                if encoded_url.startswith('a1'):
                    encoded_url = encoded_url[2:]
                
                decoded_bytes = base64.b64decode(encoded_url)
                decoded_url = decoded_bytes.decode('utf-8')

                # URL 解码 (比如 %2F 会解码成 /)
                final_url = unquote(decoded_url)

                if final_url and (final_url.startswith('http://') or final_url.startswith('https://')):
                    if "bing.com" not in final_url and "microsoft.com" not in final_url: # 再次排除Bing和微软自己的链接
                        extracted_urls.add(final_url.strip())
            except Exception as e:
                # print(f"Error decoding Bing redirect URL: {e} for {href}")
                pass # 忽略解码失败的链接

    return list(extracted_urls)

def bing_search_and_extract_urls(keywords, output_file):
    all_extracted_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for keyword in keywords:
        # 注意：Bing 的搜索 URL 可能因地区和时间而异，此处使用 www.bing.com
        search_url = f"https://www.bing.com/search?q={keyword}"
        print(f"Searching for: {keyword}")

        try:
            response = requests.get(search_url, headers=headers, timeout=15)
            response.raise_for_status()  # 检查 HTTP 错误

            # 调用新的函数来提取 URL
            urls_from_page = extract_urls_from_bing_html(response.text)
            for url in urls_from_page:
                all_extracted_urls.add(url)

            # 添加随机延迟，模拟人类行为
            time.sleep(random.uniform(3, 8)) 

        except requests.exceptions.RequestException as e:
            print(f"Error searching for {keyword}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred for {keyword}: {e}")

    # 确保 data 目录存在
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)

    # 保存去重后的 URL 到文件
    with open(os.path.join(output_dir, output_file), 'w', encoding='utf-8') as f:
        for url in sorted(list(all_extracted_urls)):
            f.write(url + '\n')
    print(f"Extracted {len(all_extracted_urls)} unique URLs and saved to {os.path.join(output_dir, output_file)}")

if __name__ == "__main__":
    keywords_to_search = ["加速器", "机场"]
    output_filename = "bing.txt"
    bing_search_and_extract_urls(keywords_to_search, output_filename)
