import requests
from bs4 import BeautifulSoup
import os
import time
import random
import base64
from urllib.parse import unquote, urlparse, parse_qs

# 导入 Selenium 相关的库
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


def decode_bing_redirect_url(bing_redirect_link):
    """
    尝试从 Bing 的重定向链接中解码出真实的网址。
    """
    try:
        # 解析 Bing 重定向链接的查询参数
        parsed_url = urlparse(bing_redirect_link)
        query_params = parse_qs(parsed_url.query)

        # 查找 'u' 参数，它包含了 Base64 编码的真实网址
        if 'u' in query_params:
            encoded_url_list = query_params['u']
            if encoded_url_list:
                encoded_url = encoded_url_list[0]
                
                # Bing 的 Base64 编码字符串有时会以 'a1' 等前缀开头，需要移除
                if encoded_url.startswith('a1'):
                    encoded_url = encoded_url[2:]
                
                # Base64 解码
                decoded_bytes = base64.b64decode(encoded_url)
                decoded_url = decoded_bytes.decode('utf-8')

                # URL 解码 (处理 %2F 等编码字符)
                final_url = unquote(decoded_url)

                # 排除 Bing 自身的链接或空的链接
                if (final_url.startswith('http://') or final_url.startswith('https://')) and \
                   "bing.com" not in final_url and "microsoft.com" not in final_url:
                    return final_url.strip()
    except Exception as e:
        # print(f"解码 Bing 重定向链接失败 ({bing_redirect_link}): {e}")
        pass
    return None

def extract_urls_from_bing_html(html_content):
    """
    从 Bing 搜索结果的 HTML 内容中提取 URL。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找 class="gs_cit" 的 div 标签中的 data-url 属性
    for div_tag in soup.find_all('div', class_='gs_cit'):
        data_url = div_tag.get('data-url')
        if data_url and (data_url.startswith('http://') or data_url.startswith('https://')):
            extracted_urls.add(data_url.strip())

    # 策略 2: 查找 class="gs_cit_siteurl" 的 div 标签中的文本内容
    for siteurl_div in soup.find_all('div', class_='gs_cit_siteurl'):
        url_text = siteurl_div.get_text()
        if url_text and (url_text.startswith('http://') or url_text.startswith('https://')):
            extracted_urls.add(url_text.strip())

    # 策略 3: 解析 Bing 的重定向链接
    for link_tag in soup.find_all('a', href=True):
        href = link_tag['href']
        if "bing.com/ck/a?" in href and "u=" in href:
            decoded_url = decode_bing_redirect_url(href)
            if decoded_url:
                extracted_urls.add(decoded_url)
                
    return list(extracted_urls)

def bing_search_and_extract_urls(keywords, output_file):
    all_extracted_urls = set()
    
    # 设置 Chrome 浏览器选项
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # 无头模式，不显示浏览器界面
    chrome_options.add_argument("--no-sandbox") # 在 Docker/GitHub Actions 环境中需要
    chrome_options.add_argument("--disable-dev-shm-usage") # 避免 /dev/shm 内存不足
    chrome_options.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80,120)}.0.4472.124 Safari/537.36") # 随机User-Agent
    chrome_options.add_argument("--window-size=1920,1080") # 设置窗口大小
    chrome_options.add_argument("--incognito") # 无痕模式

    # 初始化 WebDriver
    # 自动下载和管理 ChromeDriver
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
    except Exception as e:
        print(f"初始化 WebDriver 失败: {e}")
        print("请检查 Chrome 浏览器和 ChromeDriver 是否正确安装或兼容。")
        return # 无法继续执行

    # 确保 data 目录存在
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)

    for keyword in keywords:
        search_url = f"https://www.bing.com/search?q={keyword}"
        print(f"正在使用 Selenium 搜索: {keyword}")

        try:
            driver.get(search_url)
            
            # 等待搜索结果加载完成
            # 可以根据页面实际情况调整等待条件，例如等待某个结果元素出现
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, "b_results")) # Bing 搜索结果通常在一个 ID 为 "b_results" 的 div 中
            )
            
            # 获取页面的完整 HTML 内容
            html_content = driver.page_source
            
            # 将抓取到的 HTML 内容保存到文件，以便调试
            html_debug_file = os.path.join(output_dir, f"bing_search_results_{keyword}.html")
            with open(html_debug_file, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"已将 '{keyword}' 的 HTML 保存到 {html_debug_file} 以供调试。")

            # 调用函数从 HTML 内容中提取 URL
            urls_from_page = extract_urls_from_bing_html(html_content)
            for url in urls_from_page:
                all_extracted_urls.add(url)

            # 添加随机延迟
            time.sleep(random.uniform(5, 10)) # Selenium 请求更慢，延迟可以适当延长

        except Exception as e:
            print(f"使用 Selenium 搜索 '{keyword}' 时发生错误: {e}")

    # 关闭浏览器
    driver.quit()

    # 保存去重后的 URL 到文件
    final_output_path = os.path.join(output_dir, output_file)
    with open(final_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(all_extracted_urls)):
            f.write(url + '\n')
    print(f"已提取 {len(all_extracted_urls)} 个不重复的网址，并保存到 {final_output_path}")

if __name__ == "__main__":
    keywords_to_search = ["加速器", "机场"]
    output_filename = "bing.txt"
    
    bing_search_and_extract_urls(keywords_to_search, output_filename)
