import requests
from bs4 import BeautifulSoup
import os
import time
import random
import base64
from urllib.parse import unquote, urlparse, parse_qs, urlunparse

# 导入 Selenium 相关的库
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException, StaleElementReferenceException


def decode_bing_redirect_url(bing_redirect_link):
    """
    尝试从 Bing 的重定向链接中解码出真实的网址。
    Bing 的重定向链接通常包含一个 'u' 参数，其值是 Base64 编码的真实 URL。
    """
    try:
        parsed_url = urlparse(bing_redirect_link)
        query_params = parse_qs(parsed_url.query)

        if 'u' in query_params:
            encoded_url_list = query_params['u']
            if encoded_url_list:
                encoded_url = encoded_url_list[0]
                
                # 检查并移除 'a1' 前缀，这是 Bing 有时会添加的
                if encoded_url.startswith('a1'):
                    encoded_url = encoded_url[2:]
                
                decoded_bytes = base64.b64decode(encoded_url)
                decoded_url = decoded_bytes.decode('utf-8')

                final_url = unquote(decoded_url)

                # 过滤掉仍然指向 Bing 或 Microsoft 的 URL，并确保是有效的 HTTP/HTTPS URL
                if (final_url.startswith('http://') or final_url.startswith('https://')) and \
                   "bing.com" not in final_url and "microsoft.com" not in final_url:
                    return final_url.strip()
    except Exception as e:
        # 捕获解码过程中可能发生的错误，例如 Base64 解码失败或编码问题
        # print(f"解码 Bing 重定向 URL 失败: {bing_redirect_link}, 错误: {e}")
        pass # 静默处理，只返回 None
    return None

def extract_urls_from_bing_html(html_content, excluded_domains):
    """
    从 Bing 搜索结果的 HTML 内容中提取、处理和过滤 URL。
    Args:
        html_content (str): Bing 搜索结果页面的 HTML 内容。
        excluded_domains (set): 包含要排除的域名的集合。
    Returns:
        list: 提取到的经过处理和过滤的不重复 URL 列表。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找主要搜索结果链接 (div.b_algo 内的 h2 > a)
    for algo_div in soup.find_all('li', class_='b_algo'):
        h2_tag = algo_div.find('h2')
        if h2_tag:
            link_tag = h2_tag.find('a', href=True)
            if link_tag:
                href = link_tag['href']
                if href and (href.startswith('http://') or href.startswith('https://')):
                    # 直接的 HTTP/HTTPS 链接
                    if "bing.com" not in href and "microsoft.com" not in href:
                        extracted_urls.add(href.strip())
                
                # Bing 的重定向链接
                if "bing.com/ck/a?" in href and "u=" in href:
                    decoded_url = decode_bing_redirect_url(href)
                    if decoded_url:
                        extracted_urls.add(decoded_url)
    
    # 策略 2: 查找页面上所有有效的链接 (a 标签的 href 属性)
    for link_tag in soup.find_all('a', href=True):
        href = link_tag['href']
        if href and (href.startswith('http://') or href.startswith('https://')):
            if "bing.com" not in href and "microsoft.com" not in href and not href.startswith("javascript:"):
                extracted_urls.add(href.strip())
        
        # 再次检查重定向链接，以防它们不在 b_algo 区域
        if "bing.com/ck/a?" in href and "u=" in href:
            decoded_url = decode_bing_redirect_url(href)
            if decoded_url:
                extracted_urls.add(decoded_url)

    # 处理和过滤 URL
    processed_urls = set()
    for url in extracted_urls:
        try:
            parsed = urlparse(url)
            # 确保 scheme 存在且是 http 或 https
            if parsed.scheme in ('http', 'https') and parsed.netloc:
                base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
                # 检查域名是否在排除列表中
                if parsed.netloc not in excluded_domains:
                    processed_urls.add(base_url)
                # else:
                #     print(f"DEBUG: 排除 URL: {url} (域名: {parsed.netloc})")
        except Exception as e:
            print(f"处理 URL '{url}' 时发生错误: {e}")
            # 如果处理失败，可以根据需要选择是否保留原始URL
            # processed_urls.add(url) 
    return sorted(list(processed_urls))

def bing_search_and_extract_urls(keywords, output_file, max_pages_per_keyword=3, page_load_timeout=30, element_wait_timeout=10, random_delay_min=3, random_delay_max=8):
    """
    使用 Selenium 在 Bing 上搜索关键词并提取 URL。
    Args:
        keywords (list): 要搜索的关键词列表。
        output_file (str): 保存提取到的 URL 的文件名。
        max_pages_per_keyword (int): 每个关键词最大抓取页数。
        page_load_timeout (int): 页面加载最大等待时间 (秒)。
        element_wait_timeout (int): 等待页面元素可见的最大等待时间 (秒)。
        random_delay_min (int): 每页抓取后随机延迟的最小值 (秒)。
        random_delay_max (int): 每页抓取后随机延迟的最大值 (秒)。
    """
    all_extracted_urls = set()
    
    # 定义需要排除的域名
    excluded_domains = {
        "en.wikipedia.org",
        "github.com",
        "bing.com",
        "microsoft.com",
        "docs.microsoft.com",
        # 根据需要添加更多排除域名
    }

    chrome_options = Options()
    # 启用无头模式，在没有图形界面的环境中运行
    chrome_options.add_argument("--headless")
    # 解决在某些环境中（如 Docker）运行 Chromium 的沙盒问题
    chrome_options.add_argument("--no-sandbox")
    # 解决 /dev/shm 空间不足的问题
    chrome_options.add_argument("--disable-dev-shm-usage")
    # 随机生成 User-Agent，模拟真实浏览器行为
    chrome_options.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80,120)}.0.4472.{random.randint(100,999)} Safari/537.36")
    # 设置窗口大小，对于无头模式可能不是严格必要，但有助于模拟桌面环境
    chrome_options.add_argument("--window-size=1920,1080")
    # 使用隐身模式，每次启动都是全新的会话，不保留历史记录、缓存等
    chrome_options.add_argument("--incognito")
    # 禁用 WebDriver 标志，防止网站检测到自动化工具
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    # 设置日志级别为 WARNING 或 ERROR，减少控制台输出噪音
    chrome_options.add_argument('--log-level=3')  # 3 表示 ERROR，2 表示 WARNING
    chrome_options.add_argument('--silent') # 可能与 log-level=3 有重叠，但有时有用
    # 禁用浏览器图形化界面
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")


    driver = None
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True) # 确保输出目录存在

    try:
        # 自动下载和管理 ChromeDriver
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # 在新文档加载前执行 JS 脚本，进一步隐藏自动化痕迹
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
            """
        })
        # 设置页面加载超时
        driver.set_page_load_timeout(page_load_timeout)

        for keyword in keywords:
            print(f"\n--- 正在使用 Selenium 搜索: {keyword} ---")
            
            # 初始化当前关键词的起始 URL
            current_search_url = f"https://www.bing.com/search?q={keyword}"
            
            for current_page_num in range(1, max_pages_per_keyword + 1):
                print(f"  正在抓取第 {current_page_num} 页...")

                try:
                    driver.get(current_search_url)

                    # 等待搜索结果区域可见，增加健壮性
                    WebDriverWait(driver, element_wait_timeout).until(
                        EC.presence_of_element_located((By.ID, "b_results"))
                    )
                    # 额外等待一段时间，确保所有动态内容加载完成
                    time.sleep(random.uniform(random_delay_min, random_delay_max)) 
                    
                    html_content = driver.page_source
                    
                    # 检查是否出现验证码或其他阻碍，可以根据页面内容进行判断
                    if "captcha" in html_content.lower() or "robot" in html_content.lower():
                        print(f"  警告：在 '{keyword}' (Page {current_page_num}) 页面可能遇到验证码，停止当前关键词的抓取。")
                        break # 遇到验证码，停止当前关键词的抓取

                    if "b_results" not in html_content:
                        print(f"  警告：'{keyword}' (Page {current_page_num}) 的 HTML 内容似乎不包含预期的搜索结果区域 (b_results)。可能已被阻止。")

                    # 提取 URL
                    urls_from_page = extract_urls_from_bing_html(html_content, excluded_domains)
                    for url in urls_from_page:
                        all_extracted_urls.add(url)

                    # 调试信息：保存截图和 HTML
                    if current_page_num == 1: # 只保存第一页的调试信息
                        screenshot_path = os.path.join(output_dir, f"bing_screenshot_{keyword}.png")
                        driver.save_screenshot(screenshot_path)
                        print(f"  已将 '{keyword}' 的第 1 页截图保存到 {screenshot_path} 以供调试。")
                        
                        html_debug_file = os.path.join(output_dir, f"bing_search_results_{keyword}_page1.html")
                        with open(html_debug_file, "w", encoding="utf-8") as f:
                            f.write(html_content)
                        print(f"  已将 '{keyword}' 的第 1 页 HTML 保存到 {html_debug_file} 以供调试。")

                    # 尝试找到下一页的链接并更新 current_search_url
                    # Bing 的翻页链接通常是 <a class="sb_pagN" href="...">下一页</a> 或 <a aria-label="Next page" href="...">
                    next_page_found = False
                    try:
                        # 优先查找 'sb_pagN' class 的链接
                        next_page_link_element = WebDriverWait(driver, element_wait_timeout).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, "a.sb_pagN"))
                        )
                        next_page_url = next_page_link_element.get_attribute('href')
                        if next_page_url:
                            current_search_url = next_page_url
                            next_page_found = True
                            print(f"  找到 '下一页' 链接: {current_search_url}")
                    except (TimeoutException, NoSuchElementException):
                        # 如果没有找到 sb_pagN，尝试找其他表示下一页的链接
                        # 例如 aria-label='Next page' 或包含 'Next'/'下一页' 文本的链接
                        try:
                            next_page_link_element = WebDriverWait(driver, element_wait_timeout).until(
                                EC.element_to_be_clickable((By.XPATH, "//a[@aria-label='Next page'] | //a[contains(text(), '下一页')] | //a[contains(text(), 'Next')]"))
                            )
                            next_page_url = next_page_link_element.get_attribute('href')
                            if next_page_url:
                                current_search_url = next_page_url
                                next_page_found = True
                                print(f"  找到其他 '下一页' 链接: {current_search_url}")
                        except (TimeoutException, NoSuchElementException, StaleElementReferenceException):
                            print("  未找到有效的下一页链接，停止当前关键词的翻页。")
                            break # 找不到下一页链接，结束当前关键词的翻页

                    if not next_page_found and current_page_num < max_pages_per_keyword:
                         print("  警告: 未找到下一页链接，但尚未达到最大页数，停止当前关键词的翻页。")
                         break # 提前结束当前关键词的翻页

                except TimeoutException:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时等待页面元素超时。可能加载缓慢或被阻止，停止翻页。")
                    break
                except WebDriverException as e:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时发生 WebDriver 错误: {e}，停止翻页。")
                    break
                except Exception as e:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时发生未知错误: {e}，停止翻页。")
                    break

    except WebDriverException as e:
        print(f"初始化 WebDriver 失败: {e}")
        print("请检查 GitHub Actions 环境中 Chrome 浏览器和 ChromeDriver 的安装与兼容性。")
    finally:
        if driver:
            driver.quit() # 确保浏览器驱动被关闭

    # 保存最终去重后的 URL 到文件
    final_output_path = os.path.join(output_dir, output_file)
    with open(final_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(all_extracted_urls)):
            f.write(url + '\n')
    print(f"\n--- 抓取完成 ---")
    print(f"已提取 {len(all_extracted_urls)} 个不重复的（格式化和过滤后）网址，并保存到 {final_output_path}")

if __name__ == "__main__":
    # 配置要搜索的关键词
    keywords_to_search = [ 
        "subscribe?token=", 
        "/s/",
        "vless config telegram", # 示例：添加更多相关关键词
        "vmess config telegram",
        "trojan config telegram",
        "ss config telegram",
        "shadowsocks config telegram",
        "v2ray config telegram",
        "free vpn config telegram",
        "proxy config telegram"
    ]
    output_filename = "bing.txt"
    max_pages = 50 # 每个关键词最多抓取的页数，可以根据需求调整

    bing_search_and_extract_urls(keywords_to_search, output_filename, max_pages_per_keyword=max_pages)
