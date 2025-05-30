import os
import re
import base64
import yaml
import json
import time
import datetime
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from github import Github
from github.GithubException import RateLimitExceededException, UnknownObjectException
from tqdm import tqdm

# 配置日志系统
logging.basicConfig(
    level=logging.DEBUG,  # 确保 DEBUG 日志生效
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("node_extractor.log", encoding="utf-8"), logging.StreamHandler()]
)

# 命令行参数解析
parser = argparse.ArgumentParser(description="GitHub 节点提取器")
parser.add_argument("--output", default="data/clash_config.yaml", help="输出的 Clash 配置文件路径")
parser.add_argument("--history", default="data/nodes_history.json", help="历史记录文件路径")
parser.add_argument("--config", default="config.yaml", help="配置文件路径")
args = parser.parse_args()

# 加载配置文件
def load_config(config_file):
    default_config = {
        "search": {
            "extensions": ["txt", "yaml", "yml", "json", "md"],
            "keywords": ["ss://", "vmess://", "trojan://"],
            "filenames": ["config", "nodes", "sub", "proxy", "subscription"],
            "generic_terms": ["proxy", "subscription", "shadowsocks", "v2ray"],
            "excluded_extensions": [
                "zip", "tar", "gz", "rar", "7z", "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico",
                "mp3", "wav", "ogg", "mp4", "avi", "mov", "mkv", "pdf", "doc", "docx", "xls",
                "xlsx", "ppt", "pptx", "exe", "dll", "so", "bin", "class", "jar", "pyc"
            ]
        },
        "query_delay_seconds": 5,  # 缩短等待时间
        "max_file_size": 2_000_000,  # 2MB
        "history_expiry_days": 30,
        "max_parallel_workers": 2,
        "max_backoff_seconds": 600,
        "max_pages_per_query": 2
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            default_config.update(user_config)
            logging.info(f"已加载配置文件：{config_file}")
        except Exception as e:
            logging.warning(f"无法加载配置文件 {config_file}：{e}，使用默认配置")
    return default_config

CONFIG = load_config(args.config)
HISTORY_FILE = args.history
OUTPUT_FILE = args.output

# 初始化 GitHub 客户端
GITHUB_TOKEN = os.getenv("BOT")
if not GITHUB_TOKEN:
    logging.error("未找到 GitHub 令牌（BOT），请设置 'BOT' 环境变量")
    exit(1)
g = Github(GITHUB_TOKEN)

# 加载历史记录
nodes_history = {}
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            nodes_history = json.load(f)
        logging.info(f"从历史记录文件 {HISTORY_FILE} 加载了 {len(nodes_history)} 个节点")
    except json.JSONDecodeError:
        logging.warning(f"无法解析 JSON 文件 {HISTORY_FILE}，使用空历史记录")
        nodes_history = {}
    except Exception as e:
        logging.error(f"加载历史记录文件 {HISTORY_FILE} 失败：{e}，使用空历史记录")
        nodes_history = {}

current_run_nodes = set()

# 协议和搜索关键词
protocol_keywords = CONFIG["search"]["keywords"]
search_keywords = protocol_keywords + [kw.split("://")[0] for kw in protocol_keywords if "://" in kw]
search_extensions = CONFIG["search"]["extensions"]
search_filenames = CONFIG["search"].get("filenames", [])
generic_terms = CONFIG["search"].get("generic_terms", [])
excluded_extensions = CONFIG["search"]["excluded_extensions"]

# 生成搜索查询
search_queries = []
override_query = os.getenv("OVERRIDE_SEARCH_QUERY")
if override_query:
    search_queries.append(override_query)
    logging.info(f"使用覆盖查询：{override_query}")
else:
    # 宽泛查询
    for kw in protocol_keywords + generic_terms:
        search_queries.append(f"{kw} in:file")
    # 关键词 + 扩展名
    for ext in search_extensions:
        for kw in search_keywords:
            search_queries.append(f"{kw} in:file extension:{ext}")
    # 关键词 + 文件名
    for fname in search_filenames:
        for kw in protocol_keywords:
            search_queries.append(f"{kw} in:file {fname}")
logging.info(f"生成了 {len(search_queries)} 个搜索查询")

# 正则表达式
NODE_PATTERN = re.compile(r"(ss://[^\s#]+|ssr://[^\s#]+|vmess://[^\s#]+|trojan://[^\s#]+|vless://[^\s#]+|hysteria://[^\s#]+)")

# 解析节点
def parse_vmess_node(node):
    if node.startswith("vmess://"):
        try:
            decoded = base64.b64decode(node[8:].strip()).decode('utf-8')
            vmess_data = json.loads(decoded)
            return {
                "name": vmess_data.get("ps", f"vmess-{time.time()}"),
                "type": "vmess",
                "server": vmess_data.get("add", "unknown"),
                "port": int(vmess_data.get("port", 0)),
                "uuid": vmess_data.get("id", ""),
                "alterId": int(vmess_data.get("aid", 0)),
                "cipher": vmess_data.get("scy", "auto"),
                "tls": vmess_data.get("tls", "") == "tls",
                "node-url": node
            }
        except Exception as e:
            logging.warning(f"解析 vmess 节点失败：{e}")
            return None
    return None

def parse_ss_node(node):
    if node.startswith("ss://"):
        try:
            parts = node[5:].split('#')
            decoded = base64.b64decode(parts[0]).decode('utf-8')
            user_info, server_port = decoded.split('@')
            server, port = server_port.split(':')
            method, password = user_info.split(':')
            name = parts[1] if len(parts) > 1 else f"ss-{time.time()}"
            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": method,
                "password": password,
                "node-url": node
            }
        except Exception as e:
            logging.warning(f"解析 ss 节点失败：{e}")
            return None
    return None

# 节点提取器接口
class NodeExtractor:
    def extract(self, content):
        raise NotImplementedError

class Base64Extractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            cleaned_text = content.replace(" ", "").replace("\n", "").replace("\r", "")
            padding_needed = 4 - (len(cleaned_text) % 4)
            if padding_needed != 4:
                cleaned_text += '=' * padding_needed
            decoded_bytes = base64.b64decode(cleaned_text, validate=True)
            decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
            links.extend(NODE_PATTERN.findall(decoded_string))
            logging.debug(f"Base64 解码内容：{decoded_string[:100]}...")
        except Exception as e:
            logging.debug(f"Base64 解码失败：{e}")
        return links

class YAMLExtractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, (dict, list)):
                def find_urls_in_yaml(item):
                    if isinstance(item, dict):
                        for key, value in item.items():
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, list):
                        for value in item:
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, str):
                        links.extend(NODE_PATTERN.findall(item))
                find_urls_in_yaml(data)
        except yaml.YAMLError as e:
            logging.debug(f"YAML 解析失败：{e}")
        return links

class JSONExtractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            data = json.loads(content)
            if isinstance(data, (dict, list)):
                def find_urls_in_json(item):
                    if isinstance(item, dict):
                        for key, value in item.items():
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_json(value)
                    elif isinstance(item, list):
                        for value in item:
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_json(value)
                    elif isinstance(item, str):
                        links.extend(NODE_PATTERN.findall(item))
                find_urls_in_json(data)
        except json.JSONDecodeError as e:
            logging.debug(f"JSON 解析失败：{e}")
        return links

extractors = [Base64Extractor(), YAMLExtractor(), JSONExtractor()]

# 处理单个搜索结果
def process_search_result(result):
    global current_run_nodes
    try:
        if result.size > CONFIG["max_file_size"]:
            logging.warning(f"跳过 {result.path}（位于 {result.repository.full_name}）：文件大小 {result.size} 超过 {CONFIG['max_file_size']} 字节")
            return

        file_content = result.decoded_content.decode('utf-8', errors='ignore')
        found_nodes = NODE_PATTERN.findall(file_content)
        current_run_nodes.update(found_nodes)
        logging.debug(f"直接正则匹配找到 {len(found_nodes)} 个节点：{found_nodes}")

        # 应用提取器
        for extractor in extractors:
            extracted_nodes = extractor.extract(file_content)
            current_run_nodes.update(extracted_nodes)
            logging.debug(f"{extractor.__class__.__name__} 提取到 {len(extracted_nodes)} 个节点：{extracted_nodes}")

        # 处理 Base64 编码内容
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}(?:={0,2})")
        for b64_str in base64_pattern.findall(file_content):
            extracted_nodes = Base64Extractor().extract(b64_str)
            current_run_nodes.update(extracted_nodes)
            logging.debug(f"Base64 片段提取到 {len(extracted_nodes)} 个节点：{extracted_nodes}")

    except UnknownObjectException as e:
        logging.warning(f"无法访问或对象不存在：{result.path}（位于 {result.repository.full_name}）：{e}")
    except Exception as e:
        logging.error(f"处理 {result.path}（位于 {result.repository.full_name}）时出错：{e}")

# 并行处理搜索结果
def process_search_results_parallel(results, max_workers):
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(tqdm(executor.map(process_search_result, results), desc="处理搜索结果", unit="文件"))
    except Exception as e:
        logging.error(f"并行处理搜索结果时出错：{e}")

# 清理过期历史记录
def clean_old_nodes(history):
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=CONFIG["history_expiry_days"])
    return {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v) > cutoff}

# 生成 Clash 配置文件
def save_as_clash_config(nodes, output_file):
    clash_config = {
        "proxies": [],
        "proxy-groups": [
            {
                "name": "auto",
                "type": "url-test",
                "proxies": [],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": ["MATCH,auto"]
    }
    for node in sorted(nodes):
        proxy = parse_vmess_node(node) or parse_ss_node(node)
        if not proxy:
            proxy = {
                "name": f"node-{len(clash_config['proxies'])}",
                "type": node.split("://")[0],
                "server": "unknown",
                "port": 0,
                "node-url": node
            }
        clash_config["proxies"].append(proxy)
        clash_config["proxy-groups"][0]["proxies"].append(proxy["name"])

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    logging.info(f"已保存 Clash 配置文件，包含 {len(clash_config['proxies'])} 个代理到 '{output_file}'")

# 主逻辑
def main():
    global current_run_nodes
    for query_idx, current_query in enumerate(search_queries):
        logging.info(f"正在 GitHub 上搜索（查询 {query_idx + 1}/{len(search_queries)}）：'{current_query}'...")
        try:
            rate_limit_before = g.get_rate_limit().core
            reset_timestamp = rate_limit_before.reset.timestamp()
            logging.info(f"查询前 - 剩余 API 调用次数：{rate_limit_before.remaining}/{rate_limit_before.limit}，重置时间：{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}")

            if rate_limit_before.remaining <= 20:
                wait_seconds = reset_timestamp - time.time() + 10
                logging.warning(f"API 调用次数不足（剩余 {rate_limit_before.remaining}），等待 {wait_seconds:.1f} 秒直到 {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}...")
                time.sleep(max(wait_seconds, 0))
                continue

            search_results = g.search_code(query=current_query, per_page=100)
            total_results = search_results.totalCount
            logging.info(f"查询 '{current_query}' 共找到 {total_results} 个结果")
            if total_results == 0:
                logging.info(f"查询 '{current_query}' 无结果，跳过处理")
                time.sleep(CONFIG["query_delay_seconds"])
                continue

            page_count = 0
            for page in range(CONFIG["max_pages_per_query"]):
                try:
                    results_page = search_results.get_page(page)
                    if not results_page:
                        break
                    logging.info(f"处理查询 '{current_query}' 的第 {page + 1} 页")
                    process_search_results_parallel(results_page, CONFIG["max_parallel_workers"])
                    page_count += 1
                    time.sleep(1)
                except Exception as e:
                    if "403" in str(e):
                        logging.warning(f"第 {page + 1} 页触发 403 Forbidden 错误，可能为次级速率限制：{e}")
                        wait_seconds = min(CONFIG["max_backoff_seconds"], 600)
                        logging.info(f"等待 {wait_seconds:.1f} 秒后重试...")
                        time.sleep(wait_seconds)
                        continue
                    logging.error(f"处理第 {page + 1} 页时出错：{e}")
                    break
            logging.info(f"完成查询 '{current_query}' 的结果处理，共处理 {page_count} 页")
            time.sleep(CONFIG["query_delay_seconds"])

        except RateLimitExceededException:
            logging.warning("GitHub API 速率限制已达上限")
            rate_limit = g.get_rate_limit().core
            reset_timestamp = rate_limit.reset.timestamp()
            wait_seconds = reset_timestamp - time.time() + 10
            logging.info(f"当前剩余 API 调用次数：{rate_limit.remaining}，等待 {wait_seconds:.1f} 秒直到 {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}...")
            time.sleep(max(wait_seconds, 0))
            continue
        except Exception as e:
            logging.error(f"搜索查询 '{current_query}' 期间发生错误：{e}")
            time.sleep(CONFIG["query_delay_seconds"])
            continue

    # 更新历史记录
    current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    newly_added_count = 0
    for node_link in current_run_nodes:
        if node_link not in nodes_history:
            newly_added_count += 1
        nodes_history[node_link] = current_timestamp

    # 清理过期记录
    nodes_history.update(clean_old_nodes(nodes_history))

    logging.info(f"\n--- 节点历史记录更新 ---")
    logging.info(f"本次运行找到 {len(current_run_nodes)} 个唯一节点")
    logging.info(f"新增到历史记录的节点：{newly_added_count}")
    logging.info(f"历史记录中总节点数：{len(nodes_history)}")

    # 保存历史记录
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(nodes_history, f, ensure_ascii=False, indent=2)
        logging.info(f"已更新历史记录并保存到 '{HISTORY_FILE}'")
    except Exception as e:
        logging.error(f"无法保存历史记录文件 {HISTORY_FILE}：{e}")

    # 保存为 Clash 配置文件
    save_as_clash_config(current_run_nodes, OUTPUT_FILE)

if __name__ == "__main__":
    main()
