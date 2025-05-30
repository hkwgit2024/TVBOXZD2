import requests
import os
import json

# GitHub API 基础 URL
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub Personal Access Token
GITHUB_TOKEN = os.getenv("BOT")

# 需要搜索的代理配置片段（提取关键部分以提高搜索效率）
search_terms = [
    "hry01.2228333.xyz:62533",
    "massdeu1.731732.xyz:19842",
    "www.xfxssr:1080",
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

# 遍历每个搜索词进行查询
for term in search_terms:
    # 构造搜索查询
    params = {
        "q": term,  # 搜索关键词
        "per_page": 100  # 每页返回最多 100 条结果
    }

    try:
        # 发送请求到 GitHub 搜索 API
        response = requests.get(SEARCH_API_URL, headers=headers, params=params)
        response.raise_for_status()  # 检查请求是否成功

        # 解析 JSON 响应
        data = response.json()

        # 提取搜索结果中的文件 URL
        for item in data.get("items", []):
            repo = item["repository"]["full_name"]  # 仓库名
            path = item["path"]  # 文件路径
            html_url = item["html_url"]  # 文件的 GitHub URL
            found_urls.append(html_url)

    except requests.exceptions.RequestException as e:
        print(f"搜索 {term} 时出错: {e}")

# 去重 URL（避免重复）
found_urls = list(set(found_urls))

# 将找到的 URL 保存到文件
with open(output_file, "w", encoding="utf-8") as f:
    for url in found_urls:
        f.write(url + "\n")

print(f"找到 {len(found_urls)} 个唯一 URL，已保存到 {output_file}")
