import json
import os
import sys
import logging
from typing import List, Dict, Any, Tuple
import asyncio
import aiohttp
from urllib.parse import urlparse

# 配置日志，默认为 INFO 级别，可通过环境变量 DEBUG=1 切换到 DEBUG 级别
logging.basicConfig(
    level=logging.DEBUG if os.getenv('DEBUG') else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# URL 缓存，避免重复验证
URL_CACHE = {}
MAX_CACHE_SIZE = 10000  # 缓存大小限制，防止内存溢出

# 定义需要排除的域名，确保输出文件中不包含不可靠的源
EXCLUDED_DOMAINS = ["agit.ai", "gitcode.net", "cccimg.com"]  # 不可信域名列表

def strip_proxy(url: str) -> str:
    """
    移除 URL 中的代理前缀（如 'https://ghproxy.com/'），提取原始 GitHub URL。
    用途：清理输入文件中的各种代理，确保后续统一添加新代理。
    """
    proxies = [
        'https://ghproxy.net/',
        'https://ghp.ci/',
        'https://mirror.ghproxy.com/',
        'https://gh.api.99988866.xyz/',
        'https://github.site/',
        'https://github.store/',
        'https://gh.llkk.cc/',
        'https://ghps.cc/',
        'https://gitmirror.com/',
        'https://gitclone.com/',
    ]
    for proxy in proxies:
        if url.startswith(proxy):
            original_url = url[len(proxy):]
            if not original_url.startswith(('http://', 'https://')):
                original_url = 'https://' + original_url
            logger.debug(f"移除代理前缀: {url} -> {original_url}")
            return original_url
    return url

def add_ghfast_prefix(url: str) -> str:
    """
    为 GitHub 相关 URL（github.com 或 raw.githubusercontent.com）添加代理前缀。
    注意：如果主代理失效，需在此处替换代理 URL（见下方 PROXIES 列表）。
    """
    # 如果主代理（如 https://ghfast.top/）失效，替换 PROXIES 列表中的第一个 URL
    # 示例：将 'https://ghfast.top/' 替换为 'https://your-new-proxy.com/'
    PROXIES = [
        'https://ghfast.top/',  # 主代理（若失效，替换此处）
        'https://ghproxy.net/',  # 备用代理 1
        'https://ghp.ci/',       # 备用代理 2
        'https://gitmirror.com/' # 备用代理 3
    ]
    parsed_url = urlparse(url)
    if parsed_url.netloc in ['github.com', 'raw.githubusercontent.com']:
        new_url = f"{PROXIES[0]}{url}"  # 默认使用第一个代理
        logger.debug(f"添加代理前缀: {url} -> {new_url}")
        return new_url
    return url

async def is_valid_url(url: str, session: aiohttp.ClientSession) -> bool:
    """
    验证 URL 是否有效且可访问，支持备用代理。
    如果主代理失效，自动尝试备用代理列表中的其他代理。
    注意：如果主代理失效，需在 add_ghfast_prefix 的 PROXIES 列表中替换。
    """
    url_to_check = strip_proxy(url)
    parsed_url = urlparse(url_to_check)
    domain = parsed_url.netloc

    # 检查 URL 格式是否有效
    if not all([parsed_url.scheme, parsed_url.netloc]):
        logger.debug(f"URL 格式无效: {url}")
        return False

    # 检查是否为排除的域名
    if domain in EXCLUDED_DOMAINS:
        logger.debug(f"URL 域名在排除列表中: {domain}")
        return False
    
    # 检查缓存
    if url_to_check in URL_CACHE:
        logger.debug(f"使用缓存结果: {url_to_check}: {URL_CACHE[url_to_check]}")
        return URL_CACHE[url_to_check] == True
    
    # 清理缓存以防止内存溢出
    if len(URL_CACHE) > MAX_CACHE_SIZE:
        URL_CACHE.clear()
        logger.info("由于大小限制，URL 缓存已清除。")

    # 定义备用代理列表（与 add_ghfast_prefix 的 PROXIES 一致）
    proxies = [
        'https://ghfast.top/',  # 主代理（若失效，替换此处）
        'https://ghproxy.net/',  # 备用代理 1
        'https://ghp.ci/',       # 备用代理 2
        'https://gitmirror.com/' # 备用代理 3
    ]
    urls_to_try = [url_to_check]
    if parsed_url.netloc in ['github.com', 'raw.githubusercontent.com']:
        urls_to_try = [f"{proxy}{url_to_check}" for proxy in proxies]

    for try_url in urls_to_try:
        try:
            async with session.head(try_url, timeout=5) as response:
                is_valid = response.status == 200
                URL_CACHE[try_url] = is_valid
                if is_valid:
                    logger.debug(f"URL 有效: {try_url}")
                    # 如果使用了代理，存储有效的代理 URL
                    URL_CACHE[url_to_check] = try_url if try_url != url_to_check else True
                    return True
                logger.debug(f"URL 无效 (状态码 {response.status}): {try_url}")
        except aiohttp.ClientError as e:
            logger.debug(f"连接失败: {try_url}: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"URL 超时: {try_url}")
        except Exception as e:
            logger.debug(f"URL {try_url} 发生未知错误: {e}")

    URL_CACHE[url_to_check] = False
    return False

async def process_file(filepath: str, session: aiohttp.ClientSession) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    读取并解析 JSON 文件，过滤有效 URL 的 sites 和 lives，提取 spider。
    """
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                logger.warning(f"文件 '{filepath}' 为空，跳过。")
                return sites, lives, spider
            
            data = json.loads(content)
            
            # 情况 1: 文件为完整配置，包含 sites、lives 或 spider
            if isinstance(data, dict) and ('sites' in data or 'lives' in data or 'spider' in data):
                all_sites = data.get('sites', [])
                all_lives = data.get('lives', [])
                all_spider = [data.get('spider', "")]
                
                # 验证并处理 sites
                tasks = [is_valid_url(site.get('api', ''), session) for site in all_sites]
                valid_results = await asyncio.gather(*tasks, return_exceptions=True)

                for site, is_valid in zip(all_sites, valid_results):
                    if is_valid:
                        site['api'] = URL_CACHE.get(site.get('api', ''), add_ghfast_prefix(strip_proxy(site.get('api', ''))))
                        sites.append(site)
                    else:
                        logger.debug(f"排除无效的 site: {site.get('name', '未命名站点')} (文件: {filepath})")

                # 验证并处理直播源
                live_tasks = []
                valid_lives = []
                for live_channel in all_lives:
                    if isinstance(live_channel, dict) and 'url' in live_channel:
                        if live_channel['url'].startswith(('proxy://', 'plugin://')):
                            logger.warning(f"排除非标准代理直播源: {live_channel.get('name', '未命名频道')} (文件: {filepath})")
                            continue
                        elif live_channel['url'].startswith(('./', '/')):
                            lives.append(live_channel)
                            logger.debug(f"接受本地直播源: {live_channel.get('name', '未命名频道')} (文件: {filepath})")
                            continue
                        live_tasks.append(is_valid_url(live_channel['url'], session))
                        valid_lives.append(live_channel)
                    elif 'channels' in live_channel or 'group' in live_channel:
                        logger.warning(f"排除非标准分组直播源: {live_channel.get('name', '未命名频道')} (文件: {filepath})")

                valid_live_results = await asyncio.gather(*live_tasks, return_exceptions=True)
                for live_channel, is_valid in zip(valid_lives, valid_live_results):
                    if is_valid:
                        live_channel['url'] = URL_CACHE.get(live_channel.get('url', ''), add_ghfast_prefix(strip_proxy(live_channel.get('url', ''))))
                        lives.append(live_channel)
                    else:
                        logger.warning(f"排除无效直播源: {live_channel.get('name', '未命名频道')} (文件: {filepath})")
                
                # 验证 spider URL
                if all_spider and all_spider[0]:
                    if all_spider[0].startswith(('http://', 'https://')):
                        spider_url = add_ghfast_prefix(strip_proxy(all_spider[0]))
                        if await is_valid_url(spider_url, session):
                            spider.append(URL_CACHE.get(spider_url, spider_url))
                            logger.debug(f"有效 spider URL: {spider_url} (文件: {filepath})")
                        else:
                            logger.warning(f"排除无效 spider URL: {all_spider[0]} (文件: {filepath})")
                    else:
                        spider.append(all_spider[0])
                        logger.debug(f"接受本地 spider 路径: {all_spider[0]} (文件: {filepath})")

            # 情况 2: 文件为单个 site 对象
            elif isinstance(data, dict) and 'api' in data and 'name' in data:
                site_url = data.get('api', '')
                if site_url:
                    is_valid = await is_valid_url(site_url, session)
                    if is_valid:
                        data['api'] = URL_CACHE.get(site_url, add_ghfast_prefix(strip_proxy(site_url)))
                        sites.append(data)
                    else:
                        logger.debug(f"排除无效单个 site: {data.get('name', '未命名站点')} (文件: {filepath})")

            else:
                logger.warning(f"文件 '{filepath}' 不包含有效配置，跳过。")

    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件 '{filepath}' 失败: {e}")
    except Exception as e:
        logger.error(f"处理文件 '{filepath}' 时发生错误: {e}")
    
    return sites, lives, spider

async def merge_files(source_files: List[str], output_file: str):
    """
    合并多个 JSON 配置文件，生成单一配置文件，并去重。
    """
    logger.info("开始合并文件...")
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    async with aiohttp.ClientSession() as session:
        tasks = [process_file(f, session) for f in source_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple):
                file_sites, file_lives, file_spider = result
                sites.extend(file_sites)
                lives.extend(file_lives)
                if file_spider and not spider:
                    spider.extend(file_spider)

    # 去重 sites 和 lives
    unique_sites = {site.get('api', ''): site for site in sites if site.get('api')}.values()
    unique_lives = {live.get('url', ''): live for live in lives if live.get('url')}.values()

    merged_data = {
        "sites": list(unique_sites),
        "lives": list(unique_lives),
        "spider": spider[0] if spider else ""
    }

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, ensure_ascii=False, indent=2)
        logger.info(f"所有配置已成功合并并保存至 '{output_file}'。")
        logger.info(f"有效 sites 数量: {len(unique_sites)}, 有效 lives 数量: {len(unique_lives)}")
    except Exception as e:
        logger.error(f"保存合并文件时发生错误: {e}")

if __name__ == "__main__":
    SOURCE_DIRECTORY = "box"  # 输入文件目录
    OUTPUT_FILE = "merged_tvbox_config.json"  # 输出文件

    # 获取 box 目录中的所有 JSON 和 TXT 文件
    if os.path.exists(SOURCE_DIRECTORY) and os.path.isdir(SOURCE_DIRECTORY):
        source_files = [
            os.path.join(SOURCE_DIRECTORY, f)
            for f in os.listdir(SOURCE_DIRECTORY)
            if f.endswith(('.json', '.txt'))
        ]
        if source_files:
            asyncio.run(merge_files(source_files, OUTPUT_FILE))
        else:
            logger.error(f"'{SOURCE_DIRECTORY}' 目录中未找到 .json 或 .txt 文件。")
    else:
        logger.error(f"'{SOURCE_DIRECTORY}' 目录不存在或不是目录，请创建并添加 JSON/TXT 文件。")
