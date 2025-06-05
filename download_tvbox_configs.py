import os
import requests
import json
from datetime import datetime

# GitHub API Token，从环境变量中获取
TOKEN = os.getenv('BOT')

# GitHub API 搜索 URL
SEARCH_URL = 'https://api.github.com/search/code'

# 搜索关键词
KEYWORDS = ['spider', 'sites', 'key', 'lives', 'ads', 'wallpaper']

# 保存目录
SAVE_DIR = './tvbox'

# 创建保存目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 搜索并下载文件
def search_and_download():
    headers = {'Authorization': f'token {TOKEN}'}
    # 构造搜索查询：文件名包含 json，扩展名为 json，且包含指定关键词
    query = 'filename:json extension:json ' + ' '.join(KEYWORDS)
    params = {'q': query, 'per_page': 100}
    
    # 发送搜索请求
    response = requests.get(SEARCH_URL, headers=headers, params=params)
    if response.status_code != 200:
        print(f"错误：API 请求失败，状态码 {response.status_code}")
        return
    
    # 解析搜索结果
    results = response.json().get('items', [])
    for item in results:
        repo = item['repository']['full_name']  # 仓库名
        path = item['path']  # 文件路径
        download_url = f'https://raw.githubusercontent.com/{repo}/main/{path}'
        
        # 下载文件
        file_response = requests.get(download_url)
        if file_response.status_code == 200:
            file_name = os.path.basename(path)  # 获取原始文件名
            save_path = os.path.join(SAVE_DIR, file_name)
            
            # 处理重名文件：如果文件已存在，添加时间戳
            if os.path.exists(save_path):
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                save_path = os.path.join(SAVE_DIR, f"{file_name}_{timestamp}")
            
            # 保存文件
            with open(save_path, 'wb') as f:
                f.write(file_response.content)
            print(f"已下载：{save_path}")
        else:
            print(f"下载失败：{download_url}")

if __name__ == '__main__':
    search_and_download()
