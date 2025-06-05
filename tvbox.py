import requests
import os
import re

# GitHub API 配置
GITHUB_TOKEN = os.getenv('BOT')  # 从环境变量获取 Token
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
SEARCH_URL = 'https://api.github.com/search/repositories'
DOWNLOAD_DIR = 'tvbox'

# 确保下载目录存在
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def sanitize_filename(filename):
    """清理文件名，移除非法字符"""
    return re.sub(r'[^\w\-\.]', '_', filename)

def download_file(url, filename):
    """下载文件并处理重名"""
    base, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(DOWNLOAD_DIR, new_filename)):
        new_filename = f"{base}_{counter}{ext}"
        counter += 1
    
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        with open(os.path.join(DOWNLOAD_DIR, new_filename), 'wb') as f:
            f.write(response.content)
        print(f"已下载: {new_filename}")
    else:
        print(f"下载失败 {url}: {response.status_code}")

def search_and_download_configs():
    """搜索并下载 TVBox 配置文件"""
    query = 'tvbox+config+language:json'  # 搜索 TVBox 相关的 JSON 配置文件
    params = {'q': query, 'per_page': 100}
    
    response = requests.get(SEARCH_URL, headers=HEADERS, params=params)
    if response.status_code != 200:
        print(f"搜索失败: {response.status_code}")
        return

    repos = response.json().get('items', [])
    for repo in repos:
        repo_name = repo['full_name']
        raw_url = f"https://raw.githubusercontent.com/{repo_name}/main/config.json"
        
        # 检查文件是否存在
        file_response = requests.head(raw_url, headers=HEADERS)
        if file_response.status_code == 200:
            filename = sanitize_filename(f"{repo_name.split('/')[-1]}_config.json")
            download_file(raw_url, filename)

if __name__ == "__main__":
    search_and_download_configs()
