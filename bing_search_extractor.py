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
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException


def decode_bing_redirect_url(bing_redirect_link):
    """
    从 Bing 的重定向链接中解码出真实的网址。
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
                print(f"  解码重定向链接: {bing_redirect_link} -> {final_url}")

                if (final_url.startswith('http://') or final_url.startswith('https://')) and \
                   "bing.com" not in final_url and "microsoft.com" not in final_url:
                    return final_url.strip()
    except Exception as e:
        print(f"  解码重定向链接 '{bing_redirect_link}' 时发生错误: {e}")
    return None


def extract_urls_from_bing_html(html_content):
    """
    从 Bing 搜索结果的 HTML 内容中提取 URL。
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    extracted_urls = set()

    # 策略 1: 查找主要搜索结果链接
    for algo_div in soup.find_all('li', class_='b_algo'):
        link_tag = algo_div.find('a', href=True)  # 直接查找 <a> 标签
        if link_tag:
            href = link_tag['href']
            if href and (href.startswith('http://') or href.startswith('https://')):
                if "bing.com" not in href and "microsoft.com" not in href:
                    extracted_urls.add(href.strip())
            if "bing.com/ck/a?" in href and "u=" in href:
                decoded_url = decode_bing_redirect_url(href)
                if decoded_url:
                    extracted_urls.add(decoded_url)

    # 策略 2: 查找所有 <a> 标签中的链接
    for link_tag in soup.find_all('a', href=True):
        href = link_tag['href']
        if href and (href.startswith('http://') or href.startswith('https://')):
            if "bing.com" not in href and "microsoft.com" not in href and not href.startswith("javascript:"):
                extracted_urls.add(href.strip())
        if "bing.com/ck/a?" in href and "u=" in href:
            decoded_url = decode_bing_redirect_url(href)
            if decoded_url:
                extracted_urls.add(decoded_url)

    return list(extracted_urls)


def bing_search_and_extract_urls(keywords, output_file, max_pages_per_keyword=3):
    """
    使用 Selenium 搜索 Bing 并提取 URL，保存到指定文件。
    """
    all_extracted_urls = set()
    
    # 配置 Chrome 选项
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(
        f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{random.randint(80,120)}.0.4472.{random.randint(100,999)} Safari/537.36"
    )
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
        
        # 隐藏 WebDriver 特征
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
                    # 加载页面
                    if current_page_num == 1:
                        driver.get(search_url)
                    else:
                        # 尝试点击“下一页”按钮
                        try:
                            next_page_link = WebDriverWait(driver, 10).until(
                                EC.element_to_be_clickable((
                                    By.XPATH,
                                    "//a[@aria-label='Next page'] | //a[contains(text(), '下一页')] | "
                                    "//a[contains(text(), 'Next')] | //a[@class='sb_pagN']"
                                ))
                            )
                            next_page_link.click()
                            print(f"  点击了 '下一页' 链接。")
                        except TimeoutException:
                            print("  未找到有效的下一页链接，停止翻页。")
                            break

                    # 等待搜索结果区域加载
                    WebDriverWait(driver, 30).until(
                        EC.presence_of_element_located((By.ID, "b_results"))
                    )

                    # 模拟滚动页面以加载动态内容
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    time.sleep(random.uniform(3, 8))

                    # 获取页面 HTML
                    html_content = driver.page_source

                    # 检查是否触发验证码
                    if "captcha" in html_content.lower():
                        print(f"  警告：'{keyword}' (Page {current_page_num}) 检测到验证码，停止抓取。")
                        break

                    # 保存第一页的截图和 HTML 以供调试
                    if current_page_num == 1:
                        screenshot_path = os.path.join(output_dir, f"bing_screenshot_{keyword}.png")
                        driver.save_screenshot(screenshot_path)
                        print(f"  已将 '{keyword}' 的第 1 页截图保存到 {screenshot_path} 以供调试。")
                        
                        html_debug_file = os.path.join(output_dir, f"bing_search_results_{keyword}_page1.html")
                        with open(html_debug_file, "w", encoding="utf-8") as f:
                            f.write(html_content)
                        print(f"  已将 '{keyword}' 的第 1 页 HTML 保存到 {html_debug_file} 以供调试。")

                    # 检查搜索结果区域是否存在
                    if "b_results" not in html_content:
                        print(f"  警告：'{keyword}' (Page {current_page_num}) 的 HTML 内容似乎不包含预期的搜索结果区域 (b_results)。")

                    # 提取 URL
                    urls_from_page = extract_urls_from_bing_html(html_content)
                    print(f"  从第 {current_page_num} 页提取到 {len(urls_from_page)} 个 URL：")
                    for url in urls_from_page[:5]:  # 打印前 5 个 URL
                        print(f"    - {url}")
                    all_extracted_urls.update(urls_from_page)

                    # 随机延迟以降低反爬风险
                    time.sleep(random.uniform(8, 15))
                    current_page_num += 1

                except TimeoutException:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时等待页面元素超时。")
                    break
                except NoSuchElementException:
                    print(f"  无法找到下一页链接，'{keyword}' (Page {current_page_num}) 的翻页结束。")
                    break
                except WebDriverException as e:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时发生 WebDriver 错误: {e}。")
                    break
                except Exception as e:
                    print(f"  搜索 '{keyword}' (Page {current_page_num}) 时发生未知错误: {e}。")
                    break

    except WebDriverException as e:
        print(f"初始化 WebDriver 失败: {e}")
        print("请检查 Chrome 浏览器和 ChromeDriver 的安装与兼容性。")
    finally:
        if driver:
            driver.quit()

    # 处理和过滤 URL
    processed_urls = set()
    excluded_domains = {
        "en.wikipedia.org",
        "github.com",
        # 可添加更多排除的域名
    }

    for url in all_extracted_urls:
        try:
            parsed = urlparse(url)
            # 排除特定域名
            if parsed.netloc not in excluded_domains:
                processed_urls.add(url)  # 保留完整 URL
            else:
                print(f"排除 URL: {url} (域名: {parsed.netloc})")
        except Exception as e:
            print(f"处理 URL '{url}' 时发生错误: {e}")
            processed_urls.add(url)  # 如果处理失败，保留原始 URL

    # 保存去重后的 URL 到文件
    final_output_path = os.path.join(output_dir, output_file)
    with open(final_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(processed_urls)):
            f.write(url + '\n')
    print(f"\n--- 抓取完成 ---")
    print(f"已提取 {len(processed_urls)} 个不重复的网址，并保存到 {final_output_path}")


if __name__ == "__main__":
    keywords_to_search = ["/api/v1/client/subscribe?token="]
    output_filename = "bing.txt"
    max_pages = 30
    
    bing_search_and_extract_urls(keywords_to_search, output_filename, max_pages_per_keyword=max_pages)
