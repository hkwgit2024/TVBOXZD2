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
    except Exception:
        # 捕获解码过程中可能发生的错误，静默处理
        pass
    return None

def extract_urls_from_bing_html(html_content):
    """
    从 Bing 搜索结果的 HTML 内容中提取原始 URL，不进行进一步的格式化和过滤。
    Args:
        html_content (str): Bing 搜索结果页面的 HTML 内容。
    Returns:
        set: 提取到的原始不重复 URL 集合。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找主要搜索结果链接 (li.b_algo 内的 h2 > a)
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
    # 这会捕获到广告、相关搜索、图片/视频链接等
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
                
    return extracted_urls

def bing_search_and_extract_urls(keywords, output_file, max_pages_per_keyword=3, page_load_timeout=45, element_wait_timeout=20, random_delay_min=8, random_delay_max=15):
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
        "support.microsoft.com",
        "go.microsoft.com",
        # 根据需要添加更多排除域名
    }

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    # 更丰富的 User-Agent 随机化
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.83",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"
    ]
    chrome_options.add_argument(f"user-agent={random.choice(user_agents)}")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--incognito")
    # 禁用各种自动化检测标志
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    chrome_options.add_argument('--log-level=3')  
    chrome_options.add_argument('--silent')
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    # 更多规避检测的参数
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-features=IsolateOrigins,site-per-process")
    chrome_options.add_argument("--enable-features=NetworkService,NetworkServiceInProcess")
    chrome_options.add_argument("--profile-directory=Default")
    
    driver = None
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True) # 确保输出目录存在

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # 移除之前的 CDP 命令，有时它反而会触发检测
        # driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        #     "source": """
        #         Object.defineProperty(navigator, 'webdriver', {
        #             get: () => undefined
        #         })
        #     """
        # })
        driver.set_page_load_timeout(page_load_timeout)

        for keyword in keywords:
            print(f"\n--- 正在使用 Selenium 搜索: {keyword} ---")
            
            current_search_url = f"https://www.bing.com/search?q={keyword}"
            
            for current_page_num in range(1, max_pages_per_keyword + 1):
                print(f"  正在抓取第 {current_page_num} 页...")

                try:
                    driver.get(current_search_url)

                    # 尝试等待搜索结果区域，或者一些代表页面加载完成的元素
                    WebDriverWait(driver, element_wait_timeout).until(
                        EC.presence_of_element_located((By.ID, "b_results"))
                    )
                    # 增加更长的随机延迟，模拟真实用户浏览
                    time.sleep(random.uniform(random_delay_min, random_delay_max)) 
                    
                    html_content = driver.page_source
                    
                    # 检查页面是否包含明确的验证码提示，而不是仅仅根据 b_results 判断
                    # 常见的验证码元素ID或文本
                    if "captcha" in html_content.lower() or "verify you are not a robot" in html_content.lower() or "enter the characters you see" in html_content.lower() or "microsoft.com/captcha" in driver.current_url:
                        print(f"  警告：在 '{keyword}' (Page {current_page_num}) 页面可能遇到验证码，停止当前关键词的抓取。")
                        break # 遇到验证码，停止当前关键词的抓取
                    
                    # 如果 b_results 区域存在但其内容为空或明显不是搜索结果，则也可能存在问题
                    b_results_element = driver.find_element(By.ID, "b_results")
                    if b_results_element and not b_results_element.text.strip():
                         print(f"  警告：'{keyword}' (Page {current_page_num}) 的 b_results 区域为空，可能已被阻止或未加载内容。")
                         # 暂时不中断，继续尝试提取，因为有时内容是动态加载的
                    
                    # 提取原始 URL
                    urls_from_page = extract_urls_from_bing_html(html_content)
                    for url in urls_from_page:
                        all_extracted_urls.add(url) # 先添加到总集合，后续统一格式化和过滤

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
                            # print(f"  找到 '下一页' 链接: {current_search_url}")
                    except (TimeoutException, NoSuchElementException, StaleElementReferenceException):
                        # 如果没有找到 sb_pagN，尝试找其他表示下一页的链接
                        try:
                            next_page_link_element = WebDriverWait(driver, element_wait_timeout).until(
                                EC.element_to_be_clickable((By.XPATH, "//a[@aria-label='Next page'] | //a[contains(text(), '下一页')] | //a[contains(text(), 'Next')]"))
                            )
                            next_page_url = next_page_link_element.get_attribute('href')
                            if next_page_url:
                                current_search_url = next_page_url
                                next_page_found = True
                                # print(f"  找到其他 '下一页' 链接: {current_search_url}")
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

    # --- URL 格式化并排除特定域名 ---
    processed_urls = set()
    for url in all_extracted_urls:
        try:
            parsed = urlparse(url)
            # 只保留 scheme (http/https) 和 netloc (域名)
            # 确保 scheme 存在且是 http 或 https
            if parsed.scheme in ('http', 'https') and parsed.netloc:
                base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
                
                # 检查域名是否在排除列表中
                if parsed.netloc not in excluded_domains:
                    processed_urls.add(base_url)
                # else:
                #     print(f"DEBUG: 排除 URL: {url} (域名: {parsed.netloc})")
            # else:
            #     print(f"DEBUG: 跳过无效 URL 格式: {url}")
        except Exception as e:
            print(f"处理 URL '{url}' 时发生错误: {e}")
            # processed_urls.add(url) # 如果处理失败，可以保留原始URL

    # 保存最终去重后的 URL 到文件
    final_output_path = os.path.join(output_dir, output_file)
    with open(final_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(processed_urls)):
            f.write(url + '\n')
    print(f"\n--- 抓取完成 ---")
    print(f"已提取 {len(processed_urls)} 个不重复的（格式化和过滤后）网址，并保存到 {final_output_path}")

if __name__ == "__main__":
    # 配置要搜索的关键词
    keywords_to_search = [ 
        "subscribe?token=", 
        "/s/"

    ]
    output_filename = "bing.txt"
    max_pages = 30 # 每个关键词最多抓取的页数

    bing_search_and_extract_urls(keywords_to_search, output_filename, max_pages_per_keyword=max_pages)
