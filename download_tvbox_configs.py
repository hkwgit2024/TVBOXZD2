import requests
import os
import re

# GitHub API 配置
GITHUB_TOKEN = os.getenv('BOT')  # 从环境变量获取 Token
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
SEARCH_URL = 'https://api.github.com/search/repositories'
DOWNLOAD_DIR = 'tvbox'

# 确保下载目录存在
try:
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
except OAuthError as e:
    print(f"创建目录 {DOWNLOAD_DIR} 失败: {e}")
    exit(1)

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
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        with open(os.path.join(DOWNLOAD_DIR, new_filename), 'wb') as f:
            f.write(response.content)
        print(f"已下载: {new_filename}")
    except requests.RequestException as e:
        print(f"下载失败 {url}: {e}")
    except OSError as e:
        print(f"写入文件 {new_filename} 失败: {e}")

def search_and_download_configs():
    """搜索并下载 TVBox 配置文件"""
    if not GITHUB_TOKEN:
        print("错误: 未设置 BOT 环境变量 (GitHub Token)")
        exit(1)

    query = 'spider+wallpaper'  # 搜索与 spider 和 wallpaper 相关的配置文件
    params = {'q': query, 'per_page': 100}
    
    try:
        response = requests.get(SEARCH_URL, headers=HEADERS, params=params)
        response.raise_for_status()  # 检查请求是否成功
    except requests.RequestException as e:
        print(f"搜索失败: {e}")
        return

    repos = response.json().get('items', [])
    for repo in repos:
        repo_name = repo['full_name']
        raw_url = f"https://raw.githubusercontent.com/{repo_name}/main/config.json"
        
        try:
            file_response = requests.head(raw_url, headers=HEADERS)
            if file_response.status_code == 200:
                filename = sanitize_filename(f"{repo_name.split('/')[-1]}_config.json")
                download_file(raw_url, filename)
        except requests.RequestException as e:
            print(f"检查文件 {raw_url} 失败: {e}")

if __name__ == "__main__":
    search_and_download_configs()
