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
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException


def decode_bing_redirect_url(bing_redirect_link):
    """
    尝试从 Bing 的重定向链接中解码出真实的网址。
    """
    try:
        parsed_url = urlparse(bing_redirect_link)
        query_params = parse_qs(parsed_url.query)

        if 'u' in query_params:
            encoded_url_list = query_params['u']
            if encoded_url_list:
                encoded_url = encoded_url_list[0]
                
                if encoded_url.startswith('a1'):
                    encoded_url = encoded_url[2:]
                
                decoded_bytes = base64.b64decode(encoded_url)
                decoded_url = decoded_bytes.decode('utf-8')

                final_url = unquote(decoded_url)

                if (final_url.startswith('http://') or final_url.startswith('https://')) and \
                   "bing.com" not in final_url and "microsoft.com" not in final_url:
                    return final_url.strip()
    except Exception as e:
        pass
    return None

def extract_urls_from_bing_html(html_content):
    """
    从 Bing 搜索结果的 HTML 内容中提取 URL。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找主要搜索结果链接
    for algo_div in soup.find_all('li', class_='b_algo'):
        h2_tag = algo_div.find('h2')
        if h2_tag:
            link_tag = h2_tag.find('a', href=True)
            if link_tag:
                href = link_tag['href']
                if href and (href.startswith('http://') or href.startswith('https://')):
                    if "bing.com" not in href and "microsoft.com" not in href:
                        extracted_urls.add(href.strip())
                if "bing.com/ck/a?" in href and "u=" in href:
                    decoded_url = decode_bing_redirect_url(href)
                    if decoded_url:
                        extracted_urls.add(decoded_url)
    
    # 策略 2: 查找广告或特殊结果区域的链接
    for link_tag in soup.find_all('a', href=True):
        href = link_tag['href']
        if href and (href.startswith('http://') or href.startswith('https://')):
            if "bing.com" not in href and "microsoft.com" not in href and not href.startswith("javascript:"):
                extracted_urls.add(href.strip())
        
        if "bing.com/ck/a?" in href and "u=" in href:
            decoded_url = decode_bing_redirect_url(href)
            if decoded_url:
                extracted_urls.add(decoded_url)

    # 旧的策略，保留但优先级降低
    for div_tag in soup.find_all('div', class_='gs_cit'):
        data_url = div_tag.get('data-url')
        if data_url and (data_url.startswith('http://') or data_url.startswith('https://')):
            extracted_urls.add(data_url.strip())

    for siteurl_div in soup.find_all('div', class_='gs_cit_siteurl'):
        url_text = siteurl_div.get_text()
        if url_text and (url_text.startswith('http://') or url_text.startswith('https://')):
            extracted_urls.add(url_text.strip())
                
    return list(extracted_urls)

def bing_search_and_extract_urls(keywords, output_file, max_pages_per_keyword=3):
    all_extracted_urls = set()
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80,120)}.0.4472.{random.randint(100,999)} Safari/537.36")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    chrome_options.add_argument('--log-level=3') 
    chrome_options.add_argument('--silent')

    driver = None
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
            """
        })

        for keyword in keywords:
            search_url = f"https://www.bing.com/search?q={keyword}"
            print(f"\n--- 正在使用 Selenium 搜索: {keyword} ---")
            
            current_page_num = 1
            while current_page_num <= max_pages_per_keyword:
                print(f"  正在抓取第 {current_page_num} 页...")

                try:
                    # 对于第一页直接get，对于后续页面通过点击或URL构建
                    if current_page_num == 1:
                        driver.get(search_url)
                    else:
                        # 对于后续页，我们需要找到并点击“下一页”链接
                        try:
                            # 尝试查找 class="sb_pagN" 的链接
                            next_page_link = WebDriverWait(driver, 10).until(
                                EC.element_to_be_clickable((By.CSS_SELECTOR, "a.sb_pagN"))
                            )
                            next_page_link.click()
                            print(f"  点击了 '下一页' 按钮。")
                        except TimeoutException:
                            # 如果没有找到 sb_pagN，尝试找其他表示下一页的链接
                            print("  未找到 class='sb_pagN' 的下一页链接。尝试查找其他翻页元素。")
                            try:
                                # 寻找文本为 "Next" 的链接，或带有特定aria-label的链接
                                next_page_link = WebDriverWait(driver, 10).until(
                                    EC.element_to_be_clickable((By.XPATH, "//a[@aria-label='Next page'] | //a[contains(text(), '下一页')] | //a[contains(text(), 'Next')]"))
                                )
                                next_page_link.click()
                                print(f"  点击了其他 '下一页' 链接。")
                            except TimeoutException:
                                print("  未找到有效的下一页链接，停止翻页。")
                                break # 找不到下一页链接，结束当前关键词的翻页

                    # 等待页面加载完成，可以等待搜索结果区域再次可见
                    WebDriverWait(driver, 30).until(
                        EC.presence_of_element_located((By.ID, "b_results")) 
                    )
                    time.sleep(random.uniform(3, 8)) # 在获取 HTML 前再等待一段时间，确保JS加载完成
                    
                    current_url = driver.current_url
                    print(f"  浏览器当前 URL for '{keyword}' (Page {current_page_num}): {current_url}")

                    # --- 修正：将 html_content 的获取移到条件判断之前 ---
                    html_content = driver.page_source 
                    
                    # 截图和 HTML 保存可以调整，这里只保存第一页的
                    if current_page_num == 1:
                        screenshot_path = os.path.join(output_dir, f"bing_screenshot_{keyword}.png")
                        driver.save_screenshot(screenshot_path)
                        print(f"  已将 '{keyword}' 的第 1 页截图保存到 {screenshot_path} 以供调试。")
                        
                        html_debug_file = os.path.join(output_dir, f"bing_search_results_{keyword}_page1.html")
                        with open(html_debug_file, "w", encoding="utf-8") as f:
                            f.write(html_content)
                        print(f"  已将 '{keyword}' 的第 1 页 HTML 保存到 {html_debug_file} 以供调试。")


                    if "b_results" not in html_content:
                        print(f"  警告：'{keyword}' (Page {current_page_num}) 的 HTML 内容似乎不包含预期的搜索结果区域 (b_results)。可能已被阻止或显示验证码。")
                    
                    urls_from_page = extract_urls_from_bing_html(html_content)
                    for url in urls_from_page:
                        all_extracted_urls.add(url)

                    time.sleep(random.uniform(5, 10)) # 每页抓取之间增加随机延迟
                    current_page_num += 1

                except TimeoutException:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时等待页面元素超时。可能加载缓慢或被阻止，停止翻页。")
                    break # 遇到超时，停止当前关键词的翻页
                except NoSuchElementException:
                    print(f"  无法找到下一页链接，'{keyword}' (Page {current_page_num}) 的翻页结束。")
                    break # 找不到下一页按钮，停止当前关键词的翻页
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
            driver.quit()

    # --- URL 格式化并排除特定域名 ---
    processed_urls = set()
    excluded_domains = {
        "en.wikipedia.org",
        "github.com",
        # 您可以在这里添加更多需要排除的域名，例如：
        # "example.com",
        # "another-site.org",
    }

    for url in all_extracted_urls:
        try:
            parsed = urlparse(url)
            # 只保留 scheme (http/https) 和 netloc (域名)
            base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
            
            # 检查域名是否在排除列表中
            if parsed.netloc not in excluded_domains:
                processed_urls.add(base_url)
            else:
                print(f"排除 URL: {url} (域名: {parsed.netloc})")
        except Exception as e:
            print(f"处理 URL '{url}' 时发生错误: {e}")
            processed_urls.add(url) # 如果处理失败，保留原始URL

    # 保存去重后的（且已格式化和过滤后的）URL 到文件
    final_output_path = os.path.join(output_dir, output_file)
    with open(final_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(processed_urls)):
            f.write(url + '\n')
    print(f"\n--- 抓取完成 ---")
    print(f"已提取 {len(processed_urls)} 个不重复的（格式化和过滤后）网址，并保存到 {final_output_path}")

if __name__ == "__main__":
    keywords_to_search = [ "subscribe?token=", "/s/"] 
    output_filename = "bing.txt"
    # 设置每个关键词最多抓取的页数
    max_pages = 30 
    
    bing_search_and_extract_urls(keywords_to_search, output_filename, max_pages_per_keyword=max_pages)
