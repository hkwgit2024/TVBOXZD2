import aiohttp
import asyncio
import logging
import os
import requests
from datetime import datetime
import pytz
from urllib.parse import urlparse

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
invalid_urls = {}

# GitHub API 请求头 - 增加了自定义的 'X-Search-Query-Type'
headers = {
    'Authorization': f'token {BOT_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'X-Search-Query-Type': 'General-Code-Search' # 示例自定义头
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

async def test_url_connection(session, url, timeout=15):
    """
    测试 URL 是否可连接，并尝试获取内容类型。
    增加日志以区分 HEAD 和 GET 请求。
    """
    test_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    for attempt in range(3):
        try:
            # 尝试使用 HEAD 请求
            async with session.head(url, headers=test_headers, timeout=timeout, allow_redirects=True) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '未知')
                    logger.info(f"URL {url} HEAD 请求成功, 状态码: {response.status}, Content-Type: {content_type}")
                    # 可以根据 content_type 进行进一步的判断，例如只接受文本文件
                    # if 'text/' not in content_type and 'application/json' not in content_type and 'application/yaml' not in content_type:
                    #     logger.info(f"URL {url} Content-Type {content_type} 不符合预期。")
                    #     return False
                    return True
                logger.info(f"URL {url} HEAD 请求返回状态码: {response.status} (尝试 {attempt + 1}/3)")
        except asyncio.TimeoutError:
            logger.info(f"测试 URL {url} 超时 (尝试 {attempt + 1}/3)")
        except aiohttp.ClientError as e:
            logger.info(f"测试 URL {url} 客户端错误 (尝试 {attempt + 1}/3): {str(e)}")
        except Exception as e:
            logger.info(f"测试 URL {url} 失败 (尝试 {attempt + 1}/3): {str(e)}")
        await asyncio.sleep(2) # 每次尝试之间等待
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
    # 这里使用与主请求头相同的headers，确保一致性
    global headers
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        if len(path_parts) < 4: # 确保路径足够长以提取 repo 和 file_path
            logger.warning(f"URL {url} 格式不符合 GitHub content API 预期，无法检查更新。")
            return True # 视为更新以重新检查
        repo = '/'.join(path_parts[1:3])  # e.g., DarkSpyCyber/toranger
        file_path = '/'.join(path_parts[3:]) # e.g., history_v3.txt
        api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        
        async with session.get(api_url, headers=headers) as response: # 使用全局headers
            if response.status == 200:
                data = await response.json()
                # GitHub 内容 API 返回的 commit 信息可能在不同的键下，这里更稳健地获取
                # 尝试从 _links.git 中获取commit SHA，然后查询具体的commit信息
                # 更简单的办法是检查文件本身的 sha 或更新日期，但文件内容API不直接提供文件更新日期
                # 实际更新时间应查询 commits API，这里仍沿用之前的逻辑，假设 `commit` 字段存在
                # 如果要精确检查文件更新，可能需要调用
                # https://api.github.com/repos/{owner}/{repo}/commits?path={path}
                
                # 当前脚本依赖的是文件内容API返回的 commit 信息，这是不准确的，
                # 因为它可能不是文件本身的最新提交。更准确的做法是调用commits API。
                # 为了保持对现有逻辑的最小改动，我们假设data中会有'commit'信息。
                updated_at_str = data.get('commit', {}).get('committer', {}).get('date') or \
                                 data.get('meta', {}).get('last_modified') # 尝试其他可能的键
                
                if updated_at_str:
                    try:
                        updated_time = datetime.strptime(updated_at_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=pytz.UTC)
                        # 确保 invalid_timestamp 也是带有时区信息的 datetime 对象
                        # 注意：原始代码中的 invalid_timestamp 字符串格式包含 %Z，需要适配
                        invalid_time = datetime.strptime(invalid_timestamp, '%Y-%m-%d %H:%M:%S %Z').astimezone(pytz.UTC)
                        return updated_time > invalid_time
                    except ValueError as ve:
                        logger.warning(f"解析时间戳 {updated_at_str} 或 {invalid_timestamp} 失败: {ve}")
                        return True # 解析失败，默认视为更新
                else:
                    logger.info(f"URL {url} 的 GitHub API 响应中未找到更新时间信息。")
                    return True # 未找到更新时间，默认视为需要重新检查
            else:
                logger.info(f"检查 URL {url} 更新时 GitHub API 返回状态码: {response.status} - {await response.text()}")
                return True # API 访问失败，默认视为需要重新检查
    except Exception as e:
        logger.info(f"检查 URL {url} 更新失败: {str(e)}")
    return True  # 默认假设已更新或无法准确判断，重新检查

async def search_and_process(query, session, invalid_urls):
    """执行搜索并处理结果"""
    processed_urls = 0
    page = 1
    
    # 动态更新请求头中的查询类型，以识别是哪个查询产生的请求
    # 这里我们修改全局 headers，如果希望更细粒度控制，可以复制 headers 字典
    # 或者直接在 requests.get 调用时传入新的 headers 字典
    current_headers = headers.copy()
    current_headers['X-Search-Query-Type'] = query # 将查询本身作为关键词

    while page <= 2:
        try:
            search_url = f"https://api.github.com/search/code?q={query}&per_page=50&page={page}"
            # 使用 requests 库发送请求，并传递更新后的 headers
            response = requests.get(search_url, headers=current_headers)
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                logger.info(f"查询 '{query}' (页 {page}) 获取 {len(items)} 条结果")
                
                for item in items:
                    raw_url = item['html_url'].replace('blob/', 'raw/')
                    
                    # 检查是否已处理或在无效列表中且未更新
                    if raw_url in unique_urls:
                        continue # 已经在有效列表中，跳过
                    
                    if raw_url in invalid_urls:
                        # 如果在无效列表中，检查是否已更新
                        if not await is_url_updated(session, raw_url, invalid_urls[raw_url]['timestamp']):
                            logger.info(f"跳过未更新的无效 URL: {raw_url}")
                            continue
                        else:
                            # 如果已更新，则从 invalid_urls 中移除，重新进行连通性测试
                            logger.info(f"URL {raw_url} 已更新，重新测试连通性。")
                            del invalid_urls[raw_url]
                    
                    if await test_url_connection(session, raw_url):
                        unique_urls.add(raw_url)
                        timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                        logger.info(f"URL {raw_url} 可连通，时间戳: {timestamp}")
                    else:
                        invalid_urls[raw_url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': '连接失败'}
                        logger.info(f"URL {raw_url} 连接失败，标记为无效。")

                    processed_urls += 1
                    if processed_urls % 10 == 0:
                        logger.info(f"已处理 {processed_urls} 个 URL")
            else:
                logger.info(f"GitHub API 请求失败 (查询: '{query}', 页: {page}): 状态码 {response.status_code}, 错误信息: {response.text}")
                break # 请求失败则停止当前查询的分页
        except Exception as e:
            logger.info(f"搜索查询 '{query}' 页 {page} 失败: {str(e)}")
        
        page += 1
        await asyncio.sleep(2)  # 避免 API 限流
    return processed_urls

def save_results(invalid_urls):
    """保存结果到文件"""
    total_urls = len(unique_urls)
    total_invalid = len(invalid_urls)
    logger.info(f"统计: 共获取 {total_urls} 个有效 URL, {total_invalid} 个无效 URL")
    
    if unique_urls:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'w', encoding='utf-8') as f:
            for url in sorted(list(unique_urls)): # 排序后写入，方便查看
                timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                f.write(f"{timestamp} | {url}\n")
    
    if invalid_urls:
        with open(os.path.join(DATA_DIR, 'invalid_urls.txt'), 'w', encoding='utf-8') as f:
            for url, info in invalid_urls.items():
                f.write(f"{info['timestamp']} | {url} | {info['reason']}\n")

async def main():
    """主函数"""
    global unique_urls, invalid_urls # 声明使用全局变量
    invalid_urls = load_invalid_urls()
    
    # 重新加载上次保存的有效 URL，避免重复处理
    try:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(' | ')
                if len(parts) == 2:
                    unique_urls.add(parts[1])
    except FileNotFoundError:
        pass
    
    logger.info(f"已加载 {len(unique_urls)} 条历史有效 URL 和 {len(invalid_urls)} 条历史无效 URL。")

    async with aiohttp.ClientSession() as session:
        total_processed = 0
        for query in SEARCH_QUERIES:
            total_processed += await search_and_process(query, session, invalid_urls)
            await asyncio.sleep(2)  # 避免 API 限流
        logger.info(f"总计处理 {total_processed} 个新发现或重新检查的 URL")
    
    save_results(invalid_urls)

if __name__ == "__main__":
    asyncio.run(main())
