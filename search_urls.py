import aiohttp
import asyncio
import logging
import os
import requests
from datetime import datetime
import pytz

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)
handler = logging.FileHandler('data/search.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

# 环境变量
BOT_TOKEN = os.getenv('BOT')
if not BOT_TOKEN:
    raise ValueError("BOT 环境变量未设置")

# 上海时区
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 数据目录
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

# 存储结果
unique_urls = set()
invalid_urls = set()

# GitHub API 请求头
headers = {
    'Authorization': f'token {BOT_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# 搜索查询
SEARCH_QUERIES = [
    'clash proxies extension:yaml in:file -manifest -skaffold -locale',
    'v2ray outbounds extension:json in:file',
    'trojan nodes extension:txt in:file',
    'sing-box outbounds extension:json in:file',
    'subscription extension:txt in:file',
    'from:freefq extension:txt in:file',
    'from:mahdibland extension:txt in:file'
]

async def test_url_connection(session, url, timeout=10):
    """测试 URL 是否可连接"""
    for attempt in range(3):
        try:
            async with session.head(url, timeout=timeout, allow_redirects=True) as response:
                if response.status == 200:
                    return True
                logger.info(f"URL {url} 返回状态码: {response.status}")
        except Exception as e:
            logger.info(f"测试 URL {url} 失败 (尝试 {attempt + 1}/3): {str(e)}")
        await asyncio.sleep(1)
    return False

def load_invalid_urls():
    """加载无效 URL"""
    invalid = {}
    try:
        with open(os.path.join(DATA_DIR, 'invalid_urls.txt'), 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(' | ')
                if len(parts) == 3:
                    timestamp, url, reason = parts
                    invalid[url] = {'timestamp': timestamp, 'reason': reason}
    except FileNotFoundError:
        pass
    return invalid

async def is_url_updated(session, url, invalid_timestamp):
    """检查 URL 是否有更新"""
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        repo = '/'.join(path_parts[1:3])  # e.g., DarkSpyCyber/toranger
        file_path = '/'.join(path_parts[3:])  # e.g., history_v3.txt
        api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        async with session.get(api_url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                updated_at = data.get('commit', {}).get('committer', {}).get('date', '')
                if updated_at:
                    updated_time = datetime.strptime(updated_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.UTC)
                    invalid_time = datetime.strptime(invalid_timestamp, '%Y-%m-%d %H:%M:%S %Z').astimezone(pytz.UTC)
                    return updated_time > invalid_time
    except Exception as e:
        logger.info(f"检查 URL {url} 更新失败: {str(e)}")
    return True  # 默认假设已更新

async def search_and_process(query, session, invalid_urls):
    """执行搜索并处理结果"""
    processed_urls = 0
    page = 1
    while page <= 2:
        try:
            search_url = f"https://api.github.com/search/code?q={query}&per_page=50&page={page}"
            response = requests.get(search_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                logger.info(f"查询 {query} 页 {page} 获取 {len(items)} 条结果")
                
                for item in items:
                    raw_url = item['html_url'].replace('blob/', 'raw/')
                    if raw_url in unique_urls or raw_url in invalid_urls:
                        continue
                    if raw_url in invalid_urls and not await is_url_updated(session, raw_url, invalid_urls[raw_url]['timestamp']):
                        logger.info(f"跳过未更新的无效 URL: {raw_url}")
                        continue
                    if await test_url_connection(session, raw_url):
                        unique_urls.add(raw_url)
                        timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                        logger.info(f"URL {raw_url} 可连通，时间戳: {timestamp}")
                    else:
                        invalid_urls[raw_url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': '连接失败'}
                    processed_urls += 1
                    if processed_urls % 10 == 0:
                        logger.info(f"已处理 {processed_urls} 个 URL")
            else:
                logger.info(f"GitHub API 请求失败 (查询: {query}, 页: {page}): {response.status_code}, {response.text}")
                break
        except Exception as e:
            logger.info(f"搜索查询 {query} 页 {page} 失败: {str(e)}")
        page += 1
    return processed_urls

def save_results(invalid_urls):
    """保存结果到文件"""
    total_urls = len(unique_urls)
    total_invalid = len(invalid_urls)
    logger.info(f"统计: 共获取 {total_urls} 个有效 URL, {total_invalid} 个无效 URL")
    
    if unique_urls:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'w', encoding='utf-8') as f:
            for url in unique_urls:
                timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                f.write(f"{timestamp} | {url}\n")
    
    if invalid_urls:
        with open(os.path.join(DATA_DIR, 'invalid_urls.txt'), 'w', encoding='utf-8') as f:
            for url, info in invalid_urls.items():
                f.write(f"{info['timestamp']} | {url} | {info['reason']}\n")

async def main():
    """主函数"""
    invalid_urls = load_invalid_urls()
    async with aiohttp.ClientSession() as session:
        total_processed = 0
        for query in SEARCH_QUERIES:
            total_processed += await search_and_process(query, session, invalid_urls)
            await asyncio.sleep(2)  # 避免 API 限流
        logger.info(f"总计处理 {total_processed} 个 URL")
    
    save_results(invalid_urls)

if __name__ == "__main__":
    asyncio.run(main())
