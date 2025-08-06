import os
import re
import time
import logging
import logging.handlers
import yaml
from urllib.parse import urlparse
from tqdm.asyncio import tqdm
import aiohttp
import asyncio

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大"""
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    # 文件处理器，支持日志文件轮转，最大10MB，保留1个备份
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 读取本地 TXT 文件
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return []

# 写入本地 TXT 文件
def write_array_to_txt_local(file_path, data_array):
    """将数组内容写入本地 TXT 文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.info(f"写入 {len(data_array)} 行到 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# 加载配置和设置日志
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.error("错误：未设置环境变量 'BOT'")
    exit(1)

# 将 URLS_PATH 修改为 'config/urls.txt'
URLS_PATH = 'config/urls.txt'

# GitHub API 基础 URL
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

async def check_url_validity(session, url):
    """异步检查 URL 是否有效，只通过响应头判断"""
    try:
        async with session.head(url, timeout=5) as response:
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text' in content_type or 'json' in content_type:
                return url
            else:
                logging.info(f"URL {url} 的 Content-Type '{content_type}' 不匹配，跳过")
                return None
    except Exception as e:
        return None

async def search_github_by_keyword(session, keyword, existing_urls, found_urls, semaphore):
    """异步按关键词搜索 GitHub"""
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {GITHUB_TOKEN}"
    }

    page = 1
    urls_to_check = []
    
    while page <= CONFIG['github']['max_search_pages']:
        # 在发送请求前，先获取信号量，控制并发
        await semaphore.acquire()
        try:
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                "per_page": CONFIG['github']['per_page'],
                "page": page
            }
            async with session.get(
                f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                headers=headers,
                params=params,
                timeout=CONFIG['github']['api_timeout']
            ) as response:
                response.raise_for_status()
                data = await response.json()
                
                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页无结果")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user, repo, branch, file_path = match.groups()
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                        
                        if re.search(r'\.(m3u8|m3u|txt|csv|json|pls|xspf)$', raw_url, re.IGNORECASE):
                            if raw_url not in existing_urls and raw_url not in found_urls:
                                urls_to_check.append(raw_url)
                        else:
                            logging.debug(f"URL {raw_url} 扩展名不匹配，跳过")

                page += 1

        except aiohttp.ClientResponseError as e:
            if e.status == 403:
                logging.error(f"GitHub API 速率限制或访问被拒绝，关键词 '{keyword}': {e}")
                # 遇到403，不再继续此关键词，但可以继续其他关键词
                return
            logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}")
            break
        except Exception as e:
            logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}")
            break
        finally:
            semaphore.release()
            
    # 异步检查 URL 的有效性
    if urls_to_check:
        tasks = [check_url_validity(session, url) for url in urls_to_check]
        valid_urls = await tqdm.gather(*tasks, desc=f"校验关键词 '{keyword}' 的URL", leave=False)
        for url in valid_urls:
            if url:
                found_urls.add(url)
                logging.info(f"发现并校验通过的新URL: {url}")

async def auto_discover_github_urls_async(urls_file_path_local):
    """从 GitHub 自动发现新的 IPTV 源 URL，使用异步方式"""
    if not GITHUB_TOKEN:
        logging.warning("未提供 GitHub token，跳过 URL 自动发现")
        return

    existing_urls = set(read_txt_to_array_local(urls_file_path_local))
    found_urls = set()
    
    logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL")
    
    concurrent_searches = CONFIG['github'].get('concurrent_searches', 5)
    semaphore = asyncio.Semaphore(concurrent_searches)
    
    async with aiohttp.ClientSession() as session:
        # 处理备用 URL (同步处理即可，数量通常不多)
        for backup_url in CONFIG.get('backup_urls', []):
            try:
                async with session.get(backup_url, timeout=10) as response:
                    response.raise_for_status()
                    content = await response.text()
                    existing_urls.update([line.strip() for line in content.split('\n') if line.strip()])
            except Exception as e:
                logging.warning(f"从备用 URL {backup_url} 获取失败: {e}")

        keywords_list = CONFIG.get('search_keywords', [])
        tasks = [search_github_by_keyword(session, keyword, existing_urls, found_urls, semaphore) for keyword in keywords_list]
        
        await asyncio.gather(*tasks)

    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL")
        write_array_to_txt_local(urls_file_path_local, updated_urls)
    else:
        logging.warning("未发现新的 IPTV 源 URL")

if __name__ == "__main__":
    asyncio.run(auto_discover_github_urls_async(URLS_PATH))
