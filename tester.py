import httpx
import asyncio
import yaml
import json
import os
import logging
import re
import time
import aiodns
import aiofiles
import psutil
import socket
import base64
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# --- 配置 ---
SOURCE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
]
DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
OUTPUT_FILE = os.path.join(DATA_DIR, "all.txt")
CLASH_CONFIG_FILE = os.path.join(DATA_DIR, "unified_clash_config.yaml")
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash")
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 15))
BATCH_SIZE = 100  # 分批测试节点，防止内存超载
DNS_CACHE_EXPIRATION = 2678400  # 31 天
HISTORY_EXPIRATION = 2678400  # 31 天

# --- 日志配置 ---
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG"),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(DATA_DIR, "test_output.log"))
    ]
)
logger = logging.getLogger(__name__)

# --- 全局变量 ---
dns_cache = {}
history_results = {}
executor = ThreadPoolExecutor(max_workers=5)
duplicate_warning_count = 0
MAX_DUPLICATE_WARNINGS = 10

# --- PyYAML 配置，防止时间戳解析为 time.Time ---
def safe_yaml_representer(dumper, data):
    if isinstance(data, datetime):
        return dumper.represent_scalar('tag:yaml.org,2002:str', str(data))
    return dumper.represent(data)

yaml.add_representer(datetime, safe_yaml_representer)

# --- 辅助函数 ---
def parse_node_info(link):
    try:
        if link.startswith("vmess://"):
            encoded_part = link[8:].strip()
            if not encoded_part:
                logger.warning(f"Vmess 链接为空: {link}")
                return None
            try:
                decoded_link = base64.b64decode(encoded_part).decode('utf-8')
            except base64.binascii.Error as e:
                logger.warning(f"Base64 解码失败: {link} - {e}")
                return None
            try:
                json_data = json.loads(decoded_link)
            except json.JSONDecodeError as e:
                logger.warning(f"JSON 解析失败: {link} - {e}")
                return None
            required_fields = ["add", "port", "id", "ps"]
            for field in required_fields:
                if field not in json_data:
                    logger.warning(f"缺少字段 {field}: {link}")
                    return None
            try:
                return {
                    "type": "vmess",
                    "address": json_data["add"],
                    "port": int(json_data["port"]),
                    "id": json_data["id"],
                    "alterId": int(json_data.get("aid", 0)),
                    "security": json_data.get("scy", "auto"),
                    "network": json_data.get("net", "tcp"),
                    "path": json_data.get("path", ""),
                    "host": json_data.get("host", ""),
                    "tls": json_data.get("tls", ""),
                    "sni": json_data.get("sni", ""),
                    "remark": str(json_data["ps"])  # 强制字符串
                }
            except (ValueError, TypeError) as e:
                logger.warning(f"字段格式错误: {link} - {e}")
                return None
        elif link.startswith("vless://"):
            parsed_url = urlparse(link)
            user_id = parsed_url.username
            server_address = parsed_url.hostname
            server_port = parsed_url.port
            params = parse_qs(parsed_url.query)
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else "未知"
            return {
                "type": "vless",
                "address": server_address,
                "port": server_port,
                "id": user_id,
                "flow": params.get("flow", [""])[0],
                "security": params.get("security", [""])[0],
                "encryption": params.get("encryption", ["none"])[0],
                "network": params.get("type", [""])[0],
                "host": params.get("host", [""])[0],
                "path": params.get("path", [""])[0],
                "sni": params.get("sni", [""])[0],
                "fp": params.get("fp", [""])[0],
                "pbk": params.get("pbk", [""])[0],
                "sid": params.get("sid", [""])[0],
                "spx": params.get("spx", [""])[0],
                "remark": str(remark)  # 强制字符串
            }
        elif link.startswith("trojan://"):
            parsed_url = urlparse(link)
            password = parsed_url.username
            server_address = parsed_url.hostname
            server_port = parsed_url.port
            params = parse_qs(parsed_url.query)
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else "未知"
            return {
                "type": "trojan",
                "address": server_address,
                "port": server_port,
                "password": password,
                "sni": params.get("sni", [""])[0],
                "flow": params.get("flow", [""])[0],
                "security": params.get("security", ["tls"])[0],
                "alpn": params.get("alpn", [""])[0],
                "remark": str(remark)  # 强制字符串
            }
        elif link.startswith("ss://"):
            encoded_part = link[5:].split('@')[0]
            server_part = link[5:].split('@')[1]
            remark_match = re.search(r'#(.*)', link)
            remark = unquote(remark_match.group(1)) if remark_match else "未知"
            try:
                decoded_auth = base64.b64decode(encoded_part).decode('utf-8')
                method, password = decoded_auth.split(':', 1)
                server_address = server_part.split(':')[0]
                server_port = server_part.split(':')[1].split('#')[0]
                return {
                    "type": "shadowsocks",
                    "address": server_address,
                    "port": int(server_port),
                    "method": method,
                    "password": password,
                    "remark": str(remark)  # 强制字符串
                }
            except Exception as e:
                logger.warning(f"Shadowsocks 解析失败: {link} - {e}")
                return None
        else:
            logger.warning(f"不支持的链接格式: {link}")
            return None
    except Exception as e:
        logger.warning(f"解析节点链接失败: {link} - {e}")
        return None

def ensure_unique_name(name, existing_names):
    global duplicate_warning_count
    if name in existing_names and duplicate_warning_count < MAX_DUPLICATE_WARNINGS:
        logger.warning(f"发现重复代理名称: {name}")
        duplicate_warning_count += 1
        if duplicate_warning_count == MAX_DUPLICATE_WARNINGS:
            logger.warning("后续重复名称警告将被忽略")
    base_name = name
    count = 1
    while name in existing_names:
        name = f"{base_name}_{count:03d}"
        count += 1
    existing_names.add(name)
    return name

def generate_clash_config(nodes):
    existing_names = set()
    proxies = []
    for index, node in enumerate(nodes):
        raw_name = node.get("remark", f"node_{index}")
        if not isinstance(raw_name, str):
            logger.warning(f"非字符串名称: {raw_name}，转换为字符串")
            raw_name = str(raw_name)
        unique_name = ensure_unique_name(raw_name, existing_names)
        proxy = {
            "name": unique_name,
            "type": node["type"],
            "server": node["address"],
            "port": int(node["port"])
        }
        if node["type"] == "vmess":
            proxy.update({
                "uuid": node["id"],
                "alterId": node.get("alterId", 0),
                "cipher": node.get("security", "auto"),
                "network": node.get("network", "tcp"),
                "ws-path": node.get("path", ""),
                "ws-headers": {"Host": node.get("host", "")} if node.get("host") else {},
                "tls": node.get("tls") == "tls",
                "servername": node.get("sni", node.get("host", node["address"]))
            })
        elif node["type"] == "vless":
            proxy.update({
                "uuid": node["id"],
                "flow": node.get("flow", ""),
                "encryption": node.get("encryption", "none"),
                "network": node.get("network", "tcp"),
                "ws-path": node.get("path", ""),
                "ws-headers": {"Host": node.get("host", "")} if node.get("host") else {},
                "tls": node.get("security") == "tls",
                "servername": node.get("sni", node["address"]),
                "fingerprint": node.get("fp", "")
            })
        elif node["type"] == "trojan":
            proxy.update({
                "password": node["password"],
                "sni": node.get("sni", node["address"]),
                "alpn": node.get("alpn", ["http/1.1"]).split(','),
                "tls": node.get("security") == "tls"
            })
        elif node["type"] == "shadowsocks":
            proxy.update({
                "cipher": node["method"],
                "password": node["password"]
            })
        proxies.append(proxy)
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "global",
        "log-level": "debug",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "auto", "type": "select", "proxies": [p["name"] for p in proxies]},
            {"name": "direct", "type": "select", "proxies": ["DIRECT"]}
        ],
        "rules": ["MATCH,auto"]
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CLASH_CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, allow_unicode=True)
    return config

async def validate_clash_config(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        for i, proxy in enumerate(config.get("proxies", [])):
            if not isinstance(proxy.get("name"), str):
                logger.error(f"代理 {i} 的 name 字段不是字符串: {type(proxy['name'])}")
                return False
            if not proxy.get("server") or not proxy.get("port"):
                logger.error(f"代理 {i} 缺少 server 或 port 字段")
                return False
        logger.info("Clash 配置文件验证通过")
        return True
    except Exception as e:
        logger.error(f"验证 Clash 配置文件失败: {e}")
        return False

async def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        return result == 0
    finally:
        sock.close()

async def start_clash_process(config_path):
    try:
        if not os.path.exists(CLASH_PATH):
            logger.error(f"Clash 可执行文件未找到: {CLASH_PATH}")
            return None, None
        if not await validate_clash_config(config_path):
            logger.error("Clash 配置文件无效，终止启动")
            return None, None
        os.chmod(CLASH_PATH, 0o755)
        clash_process = await asyncio.create_subprocess_exec(
            CLASH_PATH,
            "-f", config_path,
            "-d", ".",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        async def log_clash_output(pipe, log_level):
            while True:
                line = await pipe.readline()
                if not line:
                    break
                logger.log(log_level, f"Clash: {line.decode('utf-8').strip()}")
        asyncio.create_task(log_clash_output(clash_process.stdout, logging.DEBUG))
        asyncio.create_task(log_clash_output(clash_process.stderr, logging.ERROR))
        for _ in range(15):
            if await check_port(9090):
                logger.info("Clash API 端口 9090 已就绪")
                return clash_process, "http://127.0.0.1:9090"
            await asyncio.sleep(1)
        logger.error("Clash 启动失败：端口 9090 未监听")
        await terminate_clash_process(clash_process)
        return None, None
    except Exception as e:
        logger.error(f"启动 Clash 进程失败: {e}", exc_info=True)
        return None, None

async def terminate_clash_process(clash_process):
    if clash_process and clash_process.returncode is None:
        try:
            clash_process.terminate()
            await asyncio.wait_for(clash_process.wait(), timeout=5)
            logger.debug(f"Clash 进程 (PID: {clash_process.pid}) 已终止")
        except asyncio.TimeoutError:
            logger.warning(f"Clash 进程 (PID: {clash_process.pid}) 优雅终止超时，强制杀死")
            clash_process.kill()
            await clash_process.wait()
        except Exception as e:
            logger.error(f"终止 Clash 进程失败: {e}")

async def test_clash_api(proxy_name, api_url="http://127.0.0.1:9090"):
    async with httpx.AsyncClient(timeout=TEST_TIMEOUT_SECONDS) as client:
        for attempt in range(3):
            try:
                response = await client.get(f"{api_url}/traffic")
                if response.status_code == 200:
                    logger.info(f"Clash API 连接成功: {proxy_name}")
                    start_time = time.time()
                    response = await client.get("https://www.google.com/generate_204")
                    if response.status_code in [200, 204]:
                        delay = round((time.time() - start_time) * 1000)
                        logger.info(f"节点 {proxy_name} 测试成功，延迟: {delay}ms")
                        return True, delay
                    else:
                        logger.warning(f"节点 {proxy_name} 测试失败: HTTP {response.status_code}")
                        return False, f"HTTP Status: {response.status_code}"
                logger.warning(f"Clash API 请求失败: {response.status_code}")
            except httpx.RequestError as e:
                logger.warning(f"Clash API 第 {attempt + 1} 次尝试失败: {e}")
            await asyncio.sleep(2)
        logger.error(f"节点 {proxy_name} API 连接失败，超时")
        return False, "API 超时"

async def resolve_dns(hostname):
    current_time = time.time()
    if hostname in dns_cache and (current_time - dns_cache[hostname]["timestamp"] < DNS_CACHE_EXPIRATION):
        logger.debug(f"从缓存获取 DNS 解析结果: {hostname} -> {dns_cache[hostname]['ip']}")
        return dns_cache[hostname]["ip"]
    try:
        resolver = aiodns.DNSResolver(nameservers=['8.8.8.8', '1.1.1.1'])
        result = await resolver.query(hostname, 'A')
        ip_address = result[0].host
        dns_cache[hostname] = {"ip": ip_address, "timestamp": current_time}
        logger.debug(f"DNS 解析成功并缓存: {hostname} -> {ip_address}")
        return ip_address
    except aiodns.error.DNSError as e:
        logger.warning(f"DNS 解析失败: {hostname} - {e}")
        return None
    except Exception as e:
        logger.warning(f"DNS 解析未知错误: {hostname} - {e}")
        return None

async def load_history():
    global history_results
    if os.path.exists(HISTORY_FILE):
        async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
            try:
                history_results = json.loads(await f.read())
                for link, data in list(history_results.items()):
                    if "node_info" not in data or not isinstance(data["node_info"].get("remark"), str):
                        logger.warning(f"修复历史记录 {link} 的 remark 字段")
                        node_info = parse_node_info(link)
                        if node_info:
                            data["node_info"] = {"remark": str(node_info.get("remark", "未知")), "original_link": link}
                        else:
                            logger.warning(f"无法修复历史记录 {link}，移除")
                            del history_results[link]
                current_time = time.time()
                history_results = {
                    link: data for link, data in history_results.items()
                    if (current_time - data.get("timestamp", 0) < HISTORY_EXPIRATION)
                }
                logger.info(f"已加载 {len(history_results)} 条历史记录")
            except json.JSONDecodeError:
                logger.warning("历史记录文件损坏，重新创建")
                history_results = {}
    else:
        history_results = {}

async def save_history():
    for link, data in list(history_results.items()):
        if "node_info" not in data:
            logger.warning(f"历史记录 {link} 缺少 node_info，尝试修复")
            node_info = parse_node_info(link)
            if node_info:
                data["node_info"] = {"remark": str(node_info.get("remark", "未知")), "original_link": link}
            else:
                logger.warning(f"无法修复历史记录 {link}，移除")
                del history_results[link]
                continue
        if "original_link" not in data["node_info"]:
            data["node_info"]["original_link"] = link
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(HISTORY_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(history_results, indent=2, ensure_ascii=False))
    logger.info(f"历史结果已保存: {len(history_results)} 条记录")

async def load_dns_cache():
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        async with aiofiles.open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
            try:
                dns_cache = json.loads(await f.read())
                current_time = time.time()
                dns_cache = {
                    hostname: data for hostname, data in dns_cache.items()
                    if (current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION)
                }
                logger.info(f"已加载 {len(dns_cache)} 条 DNS 缓存")
            except json.JSONDecodeError:
                logger.warning("DNS 缓存文件损坏，重新创建")
                dns_cache = {}
    else:
        dns_cache = {}

async def save_dns_cache():
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(dns_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS 缓存已保存: {len(dns_cache)} 条记录")

async def fetch_subscription(url):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
            response.raise_for_status()
            content = response.text
            try:
                decoded_content = base64.b64decode(content).decode('utf-8')
                return decoded_content.splitlines()
            except Exception:
                return content.splitlines()
    except httpx.RequestError as e:
        logger.error(f"获取订阅链接失败 {url}: {e}")
        return []
    except Exception as e:
        logger.error(f"获取订阅 {url} 时发生未知错误: {e}", exc_info=True)
        return []

async def get_all_nodes():
    all_links = []
    for url in SOURCE_URLS:
        links = await fetch_subscription(url)
        all_links.extend(links)
    unique_nodes = {}
    for link in all_links:
        parsed = parse_node_info(link)
        if parsed and parsed.get("remark"):
            unique_key = f"{parsed['type']}_{parsed['address']}_{parsed['port']}_{parsed['id']}"
            if unique_key not in unique_nodes:
                unique_nodes[unique_key] = link
            else:
                logger.info(f"忽略重复节点: {parsed['remark']}")
    return list(unique_nodes.values())

async def test_nodes(nodes):
    test_results = []
    successful_nodes = []
    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        logger.info(f"测试批次 {i//BATCH_SIZE + 1}/{len(nodes)//BATCH_SIZE + 1}")
        parsed_nodes = []
        for j, link in enumerate(batch):
            node_info = parse_node_info(link)
            if node_info:
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", node_info["address"]):
                    resolved_ip = await resolve_dns(node_info["address"])
                    if resolved_ip:
                        node_info["address"] = resolved_ip
                    else:
                        logger.warning(f"节点 {node_info['remark']} DNS 解析失败")
                        test_results.append({"node_info": {"remark": node_info["remark"], "original_link": link}, "status": "DNS解析失败", "delay": -1})
                        continue
                parsed_nodes.append(node_info)
            else:
                test_results.append({"node_info": {"remark": f"node_{i+j+1}", "original_link": link}, "status": "解析失败", "delay": -1})
        if not parsed_nodes:
            continue
        config = generate_clash_config(parsed_nodes)
        clash_process, api_url = await start_clash_process(CLASH_CONFIG_FILE)
        if not clash_process:
            for node in parsed_nodes:
                test_results.append({"node_info": node, "status": "Clash启动失败", "delay": -1})
            continue
        for node in parsed_nodes:
            is_connected, result_info = await test_clash_api(node["remark"])
            result = {
                "node_info": node,
                "status": "成功" if is_connected else "失败",
                "delay": result_info if is_connected else -1,
                "error": result_info if not is_connected else None
            }
            test_results.append(result)
            if is_connected:
                successful_nodes.append(result)
            history_results[node["original_link"]] = {
                "node_info": node,
                "status": result["status"],
                "delay": result["delay"],
                "timestamp": time.time(),
                "error": result.get("error")
            }
        await terminate_clash_process(clash_process)
    return test_results, successful_nodes

def generate_summary(test_results):
    total_nodes = len(test_results)
    success_count = sum(1 for r in test_results if r["status"] == "成功")
    fail_count = total_nodes - success_count
    status_distribution = {}
    for r in test_results:
        status_distribution[r["status"]] = status_distribution.get(r["status"], 0) + 1
    avg_delay = -1
    successful_delays = [r["delay"] for r in test_results if r["status"] == "成功" and r["delay"] != -1]
    if successful_delays:
        avg_delay = sum(successful_delays) / len(successful_delays)
    return {
        "总节点数": total_nodes,
        "成功节点数": success_count,
        "失败节点数": fail_count,
        "状态分布": status_distribution,
        "平均延迟 (ms)": f"{avg_delay:.2f}" if avg_delay != -1 else "N/A"
    }

async def main():
    start_time = time.time()
    os.makedirs(DATA_DIR, exist_ok=True)
    await load_dns_cache()
    await load_history()
    all_nodes_links = await get_all_nodes()
    logger.info(f"共获取到 {len(all_nodes_links)} 个节点链接")
    
    nodes_to_test = []
    test_results = []
    successful_nodes = []
    
    for link in all_nodes_links:
        if link in history_results and history_results[link]["status"] == "成功" and \
           (time.time() - history_results[link].get("timestamp", 0) < HISTORY_EXPIRATION):
            logger.info(f"节点 {history_results[link]['node_info']['remark']} 近期成功，跳过测试")
            test_results.append(history_results[link])
            successful_nodes.append(history_results[link])
        else:
            nodes_to_test.append(link)
    
    logger.info(f"实际需要测试 {len(nodes_to_test)} 个节点")
    batch_results, batch_successful = await test_nodes(nodes_to_test)
    test_results.extend(batch_results)
    successful_nodes.extend(batch_successful)
    
    successful_nodes.sort(key=lambda x: x["delay"])
    async with aiofiles.open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            for result in successful_nodes:
                await f.write(f"{result['node_info']['original_link']}\n")
        else:
            await f.write("# 无可用节点\n")
            logger.info("😔 没有节点通过延迟测试，输出所有原始节点链接")
            for link in all_nodes_links:
                await f.write(f"{link}\n")
    
    await save_history()
    await save_dns_cache()
    
    summary = generate_summary(test_results)
    logger.info("\n--- 测试结果摘要 ---")
    for key, value in summary.items():
        if isinstance(value, dict):
            logger.info(f"{key}:")
            for sub_key, sub_value in value.items():
                logger.info(f"  - {sub_key}: {sub_value}")
        else:
            logger.info(f"{key}: {value}")
    logger.info(f"最终成功节点数: {len(successful_nodes)}")
    logger.info(f"总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"脚本执行失败: {e}", exc_info=True)
        async def write_error_files():
            os.makedirs(DATA_DIR, exist_ok=True)
            async with aiofiles.open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                await f.write("# 脚本执行失败，无可用节点\n")
        asyncio.run(write_error_files())
