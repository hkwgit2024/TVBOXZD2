import asyncio
import aiohttp
import json
import os
import re
import subprocess
import time
import base64
import urllib.parse
from urllib.parse import urlparse, unquote, parse_qs
import logging
from tqdm import tqdm

# 常量配置
SUB_FILE = os.path.join("data", "sub.txt")  # 输入节点文件，位于 data/sub.txt
ALL_FILE = "all.txt"  # 输出可用节点文件
DATA_DIR = "data"  # 数据目录
SINGBOX_CONFIG_PATH = os.path.join(DATA_DIR, "config.json")  # sing-box 配置文件路径
SINGBOX_LOG_PATH = os.path.join(DATA_DIR, "singbox.log")  # sing-box 日志路径
SINGBOX_PATH = "./sing-box"  # sing-box 可执行文件路径
SINGBOX_HTTP_PORT = 10809  # sing-box HTTP 代理端口
TEST_TIMEOUT = 8  # 测试超时时间（秒）
CONCURRENCY_LIMIT = 5  # 最大并发数
BATCH_SIZE = 50  # 每批次节点数
TARGET_URLS = ["https://www.cloudflare.com", "https://1.1.1.1"]  # 测试目标 URL
RETRY_ATTEMPTS = 2  # 重试次数

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(DATA_DIR, "test.log"), encoding='utf-8', errors='ignore'),
        logging.StreamHandler()
    ]
)

def log_message(message, level="info"):
    """记录日志信息"""
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)

# 创建数据目录
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# 检查 sing-box 可执行文件
if not os.path.exists(SINGBOX_PATH):
    log_message(f"错误：未找到 sing-box 可执行文件 {SINGBOX_PATH}。请确保已下载并放置在工作目录。", "error")
    log_message("建议：在 GitHub Actions 中使用 setup 步骤下载 sing-box。", "info")
    exit(1)

def base64_decode_if_needed(data: str) -> str:
    """尝试解码 Base64 字符串，处理填充问题"""
    try:
        data += '=' * (-len(data) % 4)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        log_message(f"Base64 解码失败: {e}", "warning")
        return data

def is_valid_node_url(node_url: str) -> bool:
    """验证节点 URL 的合法性"""
    try:
        parsed = urlparse(node_url)
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.netloc.split('@')[-1].split(':')[0]
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return all(0 <= int(octet) <= 255 for octet in host.split('.'))
        return re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$", host) is not None
    except Exception:
        return False

def parse_tag_info(tag: str) -> dict:
    """解析节点标签中的信息（如国家、速度、成功率）"""
    country = "未知"
    speed = None
    success_rate = None
    if "美国" in tag:
        country = "美国"
    elif "日本" in tag:
        country = "日本"
    elif "香港" in tag:
        country = "香港"
    match = re.search(r"⬇️\s*([\d.]+)\s*MB/s", tag)
    if match:
        speed = float(match.group(1))
    match = re.search(r"\|(\d+)%\|", tag)
    if match:
        success_rate = int(match.group(1))
    return {"country": country, "speed": speed, "success_rate": success_rate}

def safe_unquote(s: str) -> str:
    """安全解码 URL 编码字符串"""
    try:
        return unquote(s, encoding='utf-8', errors='ignore')
    except Exception:
        return s

def extract_node_info(node_url: str) -> dict:
    """提取节点信息"""
    if not is_valid_node_url(node_url):
        log_message(f"节点 URL 格式非法，跳过: {node_url}", "warning")
        return None
    parsed_url = urlparse(node_url)
    tag = safe_unquote(parsed_url.fragment) if parsed_url.fragment else "未知"
    node_info = {"url": node_url.strip(), "tag": tag}
    node_info.update(parse_tag_info(tag))
    return node_info

def generate_singbox_config(node_url: str) -> dict:
    """生成 sing-box 配置文件"""
    try:
        parsed_url = urlparse(node_url)
        protocol = parsed_url.scheme.lower()
        netloc = parsed_url.netloc
        query_params = parse_qs(parsed_url.query)
        user_info = netloc.split('@')[0] if '@' in netloc else ""
        host_port = netloc.split('@')[1] if '@' in netloc else netloc
        host = host_port.split(':')[0] if ':' in host_port else host_port
        port = int(host_port.split(':')[1]) if ':' in host_port else 443

        outbound_config = {
            "type": protocol,
            "server": host,
            "server_port": port
        }

        tls_settings = {
            "enabled": query_params.get('tls', ['0'])[0] == '1' or protocol in ["vless", "trojan"],
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('insecure', ['0'])[0] == '1'
        }

        if protocol == "hysteria2":
            outbound_config["password"] = user_info
            if 'obfs' in query_params:
                outbound_config["obfs"] = {
                    "type": query_params['obfs'][0],
                    "password": query_params.get('obfs-password', [''])[0]
                }
            if 'up' in query_params:
                outbound_config["up_mbps"] = int(query_params['up'][0])
            if 'down' in query_params:
                outbound_config["down_mbps"] = int(query_params['down'][0])
            outbound_config["tls"] = tls_settings

        elif protocol == "vless":
            outbound_config["uuid"] = user_info
            if 'flow' in query_params:
                outbound_config["flow"] = query_params['flow'][0]
            if 'type' in query_params:
                outbound_config["transport"] = {
                    "type": query_params['type'][0],
                    "host": query_params.get('host', [''])[0],
                    "path": query_params.get('path', [''])[0]
                }
            outbound_config["tls"] = tls_settings

        elif protocol == "vmess":
            outbound_config["type"] = "vmess"
            if user_info and '@' in netloc:
                outbound_config["uuid"] = user_info
                outbound_config["alter_id"] = 0
                outbound_config["security"] = "auto"
            else:
                vmess_raw = node_url[len("vmess://"):]
                decoded_json = base64_decode_if_needed(vmess_raw)
                try:
                    vmess_data = json.loads(decoded_json)
                    outbound_config["server"] = vmess_data.get('add', host)
                    outbound_config["server_port"] = int(vmess_data.get('port', port))
                    outbound_config["uuid"] = vmess_data.get('id', '')
                    outbound_config["alter_id"] = int(vmess_data.get('aid', 0))
                    outbound_config["security"] = vmess_data.get('scy', 'auto')
                except Exception as e:
                    log_message(f"无法解析 VMESS 节点 {node_url}: {e}", "warning")
                    return None
            if 'type' in query_params:
                outbound_config["transport"] = {
                    "type": query_params['type'][0],
                    "host": query_params.get('host', [''])[0],
                    "path": query_params.get('path', [''])[0]
                }
            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings

        elif protocol == "trojan":
            outbound_config["password"] = user_info
            outbound_config["tls"] = tls_settings

        elif protocol == "ss":
            if ':' in user_info:
                method, password = user_info.split(':', 1)
                outbound_config["method"] = method
                outbound_config["password"] = password
            if 'plugin' in query_params:
                outbound_config["plugin"] = query_params['plugin'][0]
                outbound_config["plugin_opts"] = query_params.get('plugin-opts', [''])[0]

        elif protocol == "ssr":
            ssr_raw = node_url[len("ssr://"):]
            decoded = base64_decode_if_needed(ssr_raw)
            parts = decoded.split(':')
            if len(parts) >= 6:
                outbound_config["type"] = "ssr"
                outbound_config["server"] = parts[0]
                outbound_config["server_port"] = int(parts[1])
                outbound_config["protocol"] = parts[2]
                outbound_config["method"] = parts[3]
                outbound_config["obfs"] = parts[4]
                outbound_config["password"] = base64.b64decode(parts[5].split('/')[0]).decode('utf-8', errors='ignore')
                params = parse_qs(parts[5].split('?')[1]) if '?' in parts[5] else {}
                outbound_config["obfs_param"] = params.get('obfsparam', [''])[0]
                outbound_config["protocol_param"] = params.get('protoparam', [''])[0]

        elif protocol == "socks5":
            outbound_config["type"] = "socks"
            if user_info and ':' in user_info:
                username, password = user_info.split(':', 1)
                outbound_config["username"] = username
                outbound_config["password"] = password
            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings

        else:
            log_message(f"不支持的协议: {protocol}", "warning")
            return None

        config = {
            "log": {"level": "info", "output": SINGBOX_LOG_PATH},
            "outbounds": [outbound_config]
        }
        return config
    except Exception as e:
        log_message(f"生成 sing-box 配置失败 {node_url}: {e}", "error")
        return None

async def run_singbox_test_inner(node_url: str, session: aiohttp.ClientSession) -> tuple[bool, float]:
    """运行 sing-box 测试，返回测试结果和延迟"""
    config = generate_singbox_config(node_url)
    if not config:
        return False, 0

    process = None
    start_time = time.time()
    try:
        # 检查端口是否被占用
        try:
            async with session.get(f"http://127.0.0.1:{SINGBOX_HTTP_PORT}", timeout=1):
                log_message(f"端口 {SINGBOX_HTTP_PORT} 已被占用，跳过节点 {node_url}", "error")
                return False, 0
        except aiohttp.ClientError:
            pass

        with open(SINGBOX_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        process = await asyncio.create_subprocess_exec(
            SINGBOX_PATH, 'run', '-c', SINGBOX_CONFIG_PATH,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        await asyncio.sleep(2)
        if process.returncode is not None:
            stderr_data = await process.stderr.read()
            log_message(f"sing-box 启动失败: {node_url}, 错误: {stderr_data.decode('utf-8', errors='ignore')}", "error")
            return False, 0

        proxies = {
            "http": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}",
            "https": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}"
        }
        for target_url in TARGET_URLS:
            async with session.get(target_url, proxy=proxies["https"], timeout=TEST_TIMEOUT) as response:
                if response.status == 200:
                    latency = (time.time() - start_time) * 1000
                    log_message(f"HTTP 请求成功 {node_url}，目标: {target_url}，延迟: {latency:.2f}ms")
                    return True, latency
        return False, 0

    except asyncio.TimeoutError:
        log_message(f"HTTP 请求超时: {node_url}", "warning")
        return False, 0
    except aiohttp.ClientError as e:
        log_message(f"HTTP 客户端错误 {node_url}: {e}", "warning")
        return False, 0
    except Exception as e:
        log_message(f"测试节点 {node_url} 失败: {e}", "error")
        return False, 0
    finally:
        if process and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
            except Exception as e:
                log_message(f"终止 sing-box 进程失败: {e}", "error")
        if os.path.exists(SINGBOX_CONFIG_PATH):
            try:
                os.remove(SINGBOX_CONFIG_PATH)
            except Exception as e:
                log_message(f"删除配置文件失败: {e}", "error")

async def run_singbox_test(node_url: str, session: aiohttp.ClientSession) -> tuple[bool, float]:
    """带重试的 sing-box 测试"""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        log_message(f"尝试 {attempt}/{RETRY_ATTEMPTS} 测试节点: {node_url}")
        success, latency = await run_singbox_test_inner(node_url, session)
        if success:
            return success, latency
        await asyncio.sleep(1)
    return False, 0

async def test_node_connectivity(session: aiohttp.ClientSession, node_info: dict) -> tuple[dict, float]:
    """测试单个节点连通性"""
    node_url = node_info["url"]
    success, latency = await run_singbox_test(node_url, session)
    if success:
        return node_info, latency
    return None, 0

async def process_batch(session: aiohttp.ClientSession, nodes_batch: list) -> list:
    """处理一批节点"""
    tasks = [test_node_connectivity(session, node) for node in nodes_batch]
    successful_nodes = []
    for task_future in tqdm(asyncio.as_completed(tasks), total=len(nodes_batch), desc="测试节点"):
        try:
            result, latency = await task_future
            if result:
                result["latency"] = latency
                successful_nodes.append(result)
        except Exception as e:
            log_message(f"任务处理过程中发生异常: {e}", "error")
    return successful_nodes

async def main():
    """主函数"""
    if not os.path.exists(SUB_FILE):
        log_message(f"错误：未找到输入文件 {SUB_FILE}", "error")
        exit(1)

    nodes_info = []
    seen_nodes = set()
    with open(SUB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        if not lines or all(line.strip().startswith('#') or not line.strip() for line in lines):
            log_message(f"错误：{SUB_FILE} 为空或仅包含注释", "error")
            exit(1)
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and re.match(r"^(hysteria2|vless|vmess|ss|trojan|ssr|socks5)://", line, re.IGNORECASE):
                node_info = extract_node_info(line)
                if node_info:
                    parsed = urlparse(node_info["url"])
                    query = urllib.parse.urlencode(parse_qs(parsed.query), doseq=True)
                    key = (parsed.scheme, parsed.netloc, query, node_info["tag"])
                    if key not in seen_nodes:
                        seen_nodes.add(key)
                        nodes_info.append(node_info)
    log_message(f"读取到 {len(nodes_info)} 个唯一节点")

    successful_nodes = []
    connector = aiohttp.TCPConnector(limit=CONCURRENCY_LIMIT)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(nodes_info), BATCH_SIZE):
            batch = nodes_info[i:i + BATCH_SIZE]
            log_message(f"处理批次 {i//BATCH_SIZE + 1}/{len(nodes_info)//BATCH_SIZE + 1}，节点数: {len(batch)}")
            batch_successful = await process_batch(session, batch)
            successful_nodes.extend(batch_successful)
            log_message(f"批次 {i//BATCH_SIZE + 1} 完成，当前成功节点数: {len(successful_nodes)}")
            await asyncio.sleep(1)

    successful_nodes.sort(key=lambda x: x["latency"] if x["latency"] else float('inf'))
    with open(ALL_FILE, 'w', encoding='utf-8', errors='ignore') as f:
        for node in successful_nodes:
            url = node['url'].replace('\n', '')
            f.write(f"{url}\n")
            # 记录元数据到日志
            log_message(
                f"可用节点: {url} | 国家: {node['country']} | 延迟: {node['latency']:.2f}ms"
                f"{' | 速度: ' + str(node['speed']) + 'MB/s' if node['speed'] else ''}"
                f"{' | 成功率: ' + str(node['success_rate']) + '%' if node['success_rate'] else ''}"
            )

    log_message(f"测试完成！共发现 {len(successful_nodes)} 个可用节点，保存到 {ALL_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
