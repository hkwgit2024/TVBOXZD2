import requests
import os
import json
import time
from urllib.parse import quote

# GitHub API 基础 URL
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 需要搜索的代理配置片段
search_terms = [
    "hry01.2228333.xyz:62533",
    "massdeu1.731732.xyz:19842",
    "xfxssr.me",
    "us01.sh-cloudflare.sbs:8443",
    "okanc.node-is.green:21112",
    "sq.yd.3.07.cdnlinkms001.xyz:20021",
    "nnertn.airport.lat:25388",
    "xdd.dashuai.cyou:45073",
    "th01.airport.lat:20180",
    "jpc5.426624.xyz:19842",
    "zf.leifeng888.com:50240",
    "tr01.airport.lat:20820",
    "jp.xaa.app:443",
    "zz.xinghongzf.xyz:17703"
]

# 保存结果的文件路径
output_file = "data/hy2.txt"

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 存储所有找到的 URL
found_urls = []

# 设置请求头
headers = {
    "Accept": "application/vnd.github.v3+json"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("警告：未找到 BOT 环境变量，将使用未认证请求（速率限制较低）")

# 检查速率限制
response = requests.get("https://api.github.com/rate_limit", headers=headers)
rate_limit = response.json()
print(f"速率限制: {rate_limit['rate']['remaining']} 剩余, 重置时间: {rate_limit['rate']['reset']}")

# 搜索并重试
def search_with_retry(term, page, max_retries=3):
    for attempt in range(max_retries):
        try:
            print(f"尝试搜索 {term}（第 {page} 页），第 {attempt+1} 次")
            response = requests.get(SEARCH_API_URL, headers=headers, params=params)
            response.raise_for_status()
            print(f"完成搜索 {term}（第 {page} 页），状态码: {response.status_code}")
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(f"搜索 {term}（第 {page} 页）失败，第 {attempt+1} 次重试: {e}")
                time.sleep(5 * (attempt + 1))
            else:
                raise e
        except requests.exceptions.RequestException as e:
            print(f"搜索 {term}（第 {page} 页）失败，第 {attempt+1} 次重试: {e}")
            time.sleep(5 * (attempt + 1))
    print(f"搜索 {term}（第 {page} 页）失败，已达最大重试次数")
    return {"items": []}

# 遍历搜索词
max_pages = 5
for term in search_terms:
    page = 1
    while page <= max_pages:
        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        print(f"开始搜索 {term}（第 {page} 页）")
        data = search_with_retry(term, page)
        items = data.get("items", [])
        print(f"完成搜索 {term}（第 {page} 页），找到 {len(items)} 条结果")
        if not items:
            break
        for item in items:
            html_url = item["html_url"]
            found_urls.append(html_url)
        page += 1
        time.sleep(5)

# 去重 URL
found_urls = list(set(found_urls))

# 将找到的 URL 保存到文件
with open(output_file, "w", encoding="utf-8") as f:
    for url in found_urls:
        f.write(url + "\n")

print(f"找到 {len(found_urls)} 个唯一 URL，已保存到 {output_file}")
