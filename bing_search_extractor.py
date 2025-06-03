import requests # 尽管主要使用Selenium，但requests可能在某些辅助功能上仍有用
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
from selenium.common.exceptions import TimeoutException, WebDriverException


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
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    # 随机User-Agent，模拟真实浏览器
    chrome_options.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(80,120)}.0.4472.{random.randint(100,999)} Safari/537.36")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--incognito")
    # 添加一些避免检测的参数
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)

    driver = None # 初始化 driver 为 None，以便在 finally 块中判断
    # 确保 data 目录存在
    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # 使用 JavaScript 修改 navigator.webdriver 属性，进一步避免被检测
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
            """
        })

        for keyword in keywords:
            search_url = f"https://www.bing.com/search?q={keyword}"
            print(f"正在使用 Selenium 搜索: {keyword}")

            try:
                driver.get(search_url)
                
                # 增加等待时间，并尝试等待更通用的 body 元素出现，或等待一段时间让页面渲染
                # 增加等待到 30 秒，如果还不行，可能是被彻底封锁了
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                time.sleep(random.uniform(5, 10)) # 在获取 HTML 前再等待一段时间，确保JS加载完成
                
                # 获取当前页面的 URL
                current_url = driver.current_url
                print(f"浏览器当前 URL for '{keyword}': {current_url}")

                # 截取屏幕截图以供调试
                screenshot_path = os.path.join(output_dir, f"bing_screenshot_{keyword}.png")
                driver.save_screenshot(screenshot_path)
                print(f"已将 '{keyword}' 的截图保存到 {screenshot_path} 以供调试。")
                
                # 获取页面的完整 HTML 内容
                html_content = driver.page_source
                
                # 将抓取到的 HTML 内容保存到文件，以便调试
                html_debug_file = os.path.join(output_dir, f"bing_search_results_{keyword}.html")
                with open(html_debug_file, "w", encoding="utf-8") as f:
                    f.write(html_content)
                print(f"已将 '{keyword}' 的 HTML 保存到 {html_debug_file} 以供调试。")

                # 检查 HTML 内容是否包含搜索结果的标志，例如 "b_results"
                if "b_results" not in html_content:
                    print(f"警告：'{keyword}' 的 HTML 内容似乎不包含预期的搜索结果区域 (b_results)。可能已被阻止或显示验证码。")
                
                # 调用函数从 HTML 内容中提取 URL
                urls_from_page = extract_urls_from_bing_html(html_content)
                for url in urls_from_page:
                    all_extracted_urls.add(url)

                time.sleep(random.uniform(5, 15)) # 每次搜索之间增加更长的随机延迟

            except TimeoutException:
                print(f"搜索 '{keyword}' 时等待页面元素超时。可能加载缓慢或被阻止。")
            except WebDriverException as e:
                print(f"搜索 '{keyword}' 时发生 WebDriver 错误: {e}")
                print("这可能表示浏览器或驱动程序有问题。")
            except Exception as e:
                print(f"搜索 '{keyword}' 时发生未知错误: {e}")

    except WebDriverException as e:
        print(f"初始化 WebDriver 失败: {e}")
        print("请检查 GitHub Actions 环境中 Chrome 浏览器和 ChromeDriver 的安装与兼容性。")
    finally:
        if driver:
            driver.quit() # 确保浏览器最终被关闭

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
