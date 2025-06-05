import requests
import os
import re
import json

# GitHub API 配置
GITHUB_TOKEN = os.getenv('BOT')  # 从环境变量获取 Token
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
SEARCH_URL = 'https://api.github.com/search/repositories'
CODE_SEARCH_URL = 'https://api.github.com/search/code'
DOWNLOAD_DIR = 'tvbox'

# 确保下载目录存在
try:
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
except OSError as e:
    print(f"创建目录 {DOWNLOAD_DIR} 失败: {e}")
    exit(1)

def sanitize_filename(filename):
    """清理文件名，移除非法字符"""
    return re.sub(r'[^\w\-\.]', '_', filename)

def check_file_content(file_path):
    """检查 JSON 文件内容是否同时包含 'spider' 和 'wallpaper'"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()  # 转换为小写以忽略大小写
            return 'spider' in content and 'wallpaper' in content
    except (OSError, UnicodeDecodeError) as e:
        print(f"读取文件 {file_path} 失败: {e}")
        return False

def download_file(url, filename):
    """下载文件并处理重名，检查内容后决定是否保留"""
    base, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(os.path.join(DOWNLOAD_DIR, new_filename)):
        new_filename = f"{base}_{counter}{ext}"
        counter += 1
    
    file_path = os.path.join(DOWNLOAD_DIR, new_filename)
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            f.write(response.content)
        
        # 检查文件内容
        if check_file_content(file_path):
            print(f"已下载并保留: {new_filename} (包含 spider 和 wallpaper)")
            return True
        else:
            print(f"删除 {new_filename}: 不包含 spider 和 wallpaper")
            os.remove(file_path)
            return False
    except requests.RequestException as e:
        print(f"下载失败 {url}: {e}")
        return False
    except OSError as e:
        print(f"写入文件 {new_filename} 失败: {e}")
        return False

def search_and_download_configs():
    """搜索并下载 TVBox 配置文件"""
    if not GITHUB_TOKEN:
        print("错误: 未设置 BOT 环境变量 (GitHub Token)")
        exit(1)

    # 搜索仓库
    query = 'tvbox+spider+wallpaper'  # 搜索 TVBox 相关的仓库，包含 spider 和 wallpaper
    params = {'q': query, 'per_page': 100}
    
    try:
        response = requests.get(SEARCH_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        repos = response.json().get('items', [])
        print(f"找到 {len(repos)} 个仓库")
    except requests.RequestException as e:
        print(f"仓库搜索失败: {e}")
        return

    for repo in repos:
        repo_name = repo['full_name']
        print(f"检查仓库: {repo_name}")
        
        # 搜索 JSON 文件
        code_query = f'repo:{repo_name} filename:*.json'  # 搜索所有 JSON 文件
        try:
            code_response = requests.get(CODE_SEARCH_URL, headers=HEADERS, params={'q': code_query})
            if code_response.status_code == 403:
                print(f"跳过 {repo_name}: 403 Forbidden (可能是私有仓库或权限不足)")
                continue
            code_response.raise_for_status()
            files = code_response.json().get('items', [])
            print(f"仓库 {repo_name} 找到 {len(files)} 个 JSON 文件")
            
            for file in files:
                if file['name'].endswith('.json'):
                    raw_url = file['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    filename = sanitize_filename(f"{repo_name.split('/')[-1]}_{file['name']}")
                    download_file(raw_url, filename)
                else:
                    print(f"跳过非 JSON 文件: {file['name']} 在 {repo_name}")
        except requests.RequestException as e:
            print(f"代码搜索失败 {repo_name}: {e}")

if __name__ == "__main__":
    search_and_download_configs()
