import requests
import os
import json
import time
from urllib.parse import quote

# GitHub API 基础 URL
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 需要搜索的代理配置片段（只使用域名部分以提高匹配率）
search_terms = [
    "hry01.2228333.xyz",
    "massdeu1.731732.xyz",
    "www.xfxssr",
    "us01.sh-cloudflare.sbs",
    "okanc.node-is.green",
    "sq.yd.3.07.cdnlinkms001.xyz",
    "nnertn.airport.lat",
    "xdd.dashuai.cyou",
    "th01.airport.lat",
    "jpc5.426624.xyz",
    "zf.leifeng888.com",
    "tr01.airport.lat",
    "jp.xaa.app",
    "zz.xinghongzf.xyz"
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

# 遍历每个搜索词进行查询
for term in search_terms:
    page = 1
    while True:
        params = {
            "q": quote(term, safe=''),
            "per_page": 100,
            "page": page
        }
        try:
            response = requests.get(SEARCH_API_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                html_url = item["html_url"]
                found_urls.append(html_url)
            page += 1
            time.sleep(2)  # 每页请求间隔 2 秒
        except requests.exceptions.RequestException as e:
            print(f"搜索 {term}（第 {page} 页）时出错: {e}")
            break

# 去重 URL
found_urls = list(set(found_urls))

# 将找到的 URL 保存到文件
with open(output_file, "w", encoding="utf-8") as f:
    for url in found_urls:
        f.write(url + "\n")

print(f"找到 {len(found_urls)} 个唯一 URL，已保存到 {output_file}")
