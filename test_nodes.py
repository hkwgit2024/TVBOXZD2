import httpx
import asyncio
import json
import os
import logging
import re
import time
import aiodns
import aiofiles
import psutil
import socket
import ssl
import subprocess
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor
import base64
from functools import partial

# --- 配置 ---
SOURCE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
]

DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")
SUCCESS_COUNT_FILE = os.path.join(DATA_DIR, "success_count.txt")

TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 15))
BATCH_SIZE = 100
DNS_CACHE_EXPIRATION = 2678400  # 31 天
HISTORY_EXPIRATION = 2678400  # 31 天

XRAY_PATH = os.getenv("XRAY_PATH", "./xray")
XRAY_GEOIP_PATH = os.getenv("XRAY_GEOIP_PATH", os.path.join(DATA_DIR, "geoip-lite.dat"))
XRAY_GEOSITE_PATH = os.getenv("XRAY_GEOSITE_PATH", os.path.join(DATA_DIR, "geosite.dat"))

# --- 日志配置 ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

# --- 全局变量 ---
dns_cache = {}
history_results = {}
executor = ThreadPoolExecutor(max_workers=10) # 限制并发 DNS 解析

# --- 辅助函数 ---
def parse_node_info(link):
    try:
        if link.startswith("vmess://"):
            decoded_link = base64.b64decode(link[8:]).decode('utf-8')
            json_data = json.loads(decoded_link)
            return {
                "type": "vmess",
                "address": json_data.get("add"),
                "port": json_data.get("port"),
                "id": json_data.get("id"),
                "alterId": json_data.get("aid"),
                "security": json_data.get("scy", "auto"),
                "network": json_data.get("net"),
                "path": json_data.get("path"),
                "host": json_data.get("host"),
                "tls": json_data.get("tls", ""),
                "sni": json_data.get("sni", ""),
                "remark": json_data.get("ps", "未知")
            }
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
                "remark": remark,
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
                "security": params.get("security", ["tls"])[0], # Trojan 默认TLS
                "alpn": params.get("alpn", [""])[0],
                "remark": remark
            }
        elif link.startswith("ss://"):
            # SS 格式通常是 base64(method:password)@server:port#remark
            encoded_part = link[5:].split('@')[0]
            server_part = link[5:].split('@')[1]
            remark_match = re.search(r'#(.*)', link)
            remark = unquote(remark_match.group(1)) if remark_match else "未知"

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
                "remark": remark
            }
        else:
            return None
    except Exception as e:
        logger.warning(f"解析节点链接失败: {link} - {e}")
        return None

def generate_xray_config(node_info):
    if not node_info:
        return None

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": 1080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            },
            {
                "port": 1081,
                "protocol": "http",
                "settings": {"accounts": [{"user": "user", "pass": "pass"}]},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }
        ],
        "outbounds": [{
            "protocol": node_info["type"],
            "settings": {},
            "streamSettings": {"network": node_info.get("network", "tcp")},
            "tag": "proxy"
        }],
        "routing": {
            "rules": [
                {"type": "field", "outboundTag": "proxy", "port": "80,443", "network": "tcp,udp"}
            ]
        }
    }

    outbound_settings = config["outbounds"][0]["settings"]
    stream_settings = config["outbounds"][0]["streamSettings"]

    if node_info["type"] == "vmess":
        outbound_settings["vnext"] = [{
            "address": node_info["address"],
            "port": node_info["port"],
            "users": [{
                "id": node_info["id"],
                "alterId": int(node_info["alterId"]),
                "security": node_info["security"]
            }]
        }]
        if node_info.get("tls") == "tls":
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {"serverName": node_info.get("sni", node_info.get("host", ""))}
        if node_info.get("network") == "ws":
            stream_settings["wsSettings"] = {"path": node_info.get("path", "/"), "headers": {"Host": node_info.get("host", "")}}
        elif node_info.get("network") == "http":
            stream_settings["httpSettings"] = {"path": node_info.get("path", "/"), "host": [node_info.get("host", "")]}
        elif node_info.get("network") == "h2":
            stream_settings["h2Settings"] = {"path": node_info.get("path", "/"), "host": [node_info.get("host", "")]}
        elif node_info.get("network") == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": node_info.get("path", "")}


    elif node_info["type"] == "vless":
        outbound_settings["vnext"] = [{
            "address": node_info["address"],
            "port": node_info["port"],
            "users": [{
                "id": node_info["id"],
                "encryption": node_info.get("encryption", "none"),
                "flow": node_info.get("flow", "")
            }]
        }]
        if node_info.get("security") == "tls":
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": node_info.get("sni", node_info.get("address", "")),
                "fingerprint": node_info.get("fp", ""),
                "show": True
            }
        elif node_info.get("security") == "reality":
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "dest": f"{node_info.get('address')}:{node_info.get('port')}",
                "xver": 0,
                "serverNames": [node_info.get("sni", "")],
                "privateKey": "", # REALITY 需要私钥，这里留空，因为测试不需要实际连接
                "shortIds": [node_info.get("sid", "")]
            }
        
        if node_info.get("network") == "ws":
            stream_settings["wsSettings"] = {"path": node_info.get("path", "/"), "headers": {"Host": node_info.get("host", "")}}
        elif node_info.get("network") == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": node_info.get("path", "")}
            
    elif node_info["type"] == "trojan":
        outbound_settings["servers"] = [{
            "address": node_info["address"],
            "port": node_info["port"],
            "password": node_info["password"]
        }]
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": node_info.get("sni", node_info.get("address", "")),
            "alpn": node_info.get("alpn", ["http/1.1"]).split(',')
        }
        if node_info.get("flow"):
            stream_settings["realitySettings"] = {"flow": node_info.get("flow")} # 假设trojan的flow也是reality的一部分

    elif node_info["type"] == "shadowsocks":
        outbound_settings["servers"] = [{
            "address": node_info["address"],
            "port": node_info["port"],
            "method": node_info["method"],
            "password": node_info["password"]
        }]
        # SS通常不需要复杂的streamSettings，除非有插件
    
    # 添加直连和黑洞出站，以防规则匹配失败
    config["outbounds"].append({"protocol": "freedom", "tag": "direct"})
    config["outbounds"].append({"protocol": "blackhole", "tag": "block"})

    config["routing"]["rules"].append({"type": "field", "ip": ["geoip:private"], "outboundTag": "block"})
    config["routing"]["rules"].append({"type": "field", "domain": ["geosite:private"], "outboundTag": "block"})
    config["routing"]["rules"].append({"type": "field", "outboundTag": "direct", "network": "tcp,udp"})


    return json.dumps(config, indent=2)

async def check_connectivity(proxy_url, test_url="https://www.google.com/generate_204"):
    try:
        async with httpx.AsyncClient(proxies={"http://": proxy_url, "https://": proxy_url}, timeout=TEST_TIMEOUT_SECONDS) as client:
            start_time = time.time()
            response = await client.get(test_url)
            end_time = time.time()
            if response.status_code == 204:
                return True, round((end_time - start_time) * 1000)  # 返回毫秒
            else:
                return False, f"HTTP Status: {response.status_code}"
    except httpx.ConnectError:
        return False, "连接错误"
    except httpx.TimeoutException:
        return False, "连接超时"
    except httpx.RequestError as e:
        return False, f"请求错误: {e}"
    except Exception as e:
        return False, f"未知错误: {e}"

async def resolve_dns(hostname):
    current_time = time.time()
    if hostname in dns_cache and (current_time - dns_cache[hostname]["timestamp"] < DNS_CACHE_EXPIRATION):
        logger.debug(f"从缓存获取 DNS 解析结果: {hostname} -> {dns_cache[hostname]['ip']}")
        return dns_cache[hostname]["ip"]

    try:
        # 使用 aiodns 进行异步 DNS 解析
        resolver = aiodns.resolver.Resolver()
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

async def start_proxy_subprocess(config_content):
    try:
        # 确保XRAY_PATH是可执行的
        if not os.path.exists(XRAY_PATH):
            logger.error(f"Xray 可执行文件未找到: {XRAY_PATH}")
            return None, None
        os.chmod(XRAY_PATH, 0o755)

        # 启动 Xray 进程
        xray_process = await asyncio.create_subprocess_exec(
            XRAY_PATH,
            "-config", "stdin:",
            env={
                "XRAY_LOCATION_ASSET": DATA_DIR,
                "XRAY_GEOIP_PATH": XRAY_GEOIP_PATH,
                "XRAY_GEOSITE_PATH": XRAY_GEOSITE_PATH,
            },
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        xray_process.stdin.write(config_content.encode('utf-8'))
        await xray_process.stdin.drain()
        xray_process.stdin.close()
        
        # 捕获 stderr 输出，以便调试
        # stderr_output = await xray_process.stderr.read()
        # if stderr_output:
        #     logger.debug(f"Xray stderr: {stderr_output.decode().strip()}")

        # 稍微等待一下，确保Xray完全启动并监听端口
        await asyncio.sleep(1) # 增加等待时间

        return xray_process, f"socks5://127.0.0.1:1080"
    except Exception as e:
        logger.error(f"启动 Xray 进程失败: {e}", exc_info=True)
        return None, None

async def terminate_xray_process(xray_process):
    if xray_process and xray_process.returncode is None:
        try:
            # 尝试优雅终止
            xray_process.terminate()
            try:
                await asyncio.wait_for(xray_process.wait(), timeout=5)
            except asyncio.TimeoutError:
                logger.warning(f"Xray 进程 (PID: {xray_process.pid}) 优雅终止超时，尝试强制杀死。")
                xray_process.kill()
                await xray_process.wait()
            logger.debug(f"Xray 进程 (PID: {xray_process.pid}) 已终止。")
        except ProcessLookupError:
            logger.debug(f"Xray 进程 (PID: {xray_process.pid}) 已经不存在。")
        except Exception as e:
            logger.error(f"终止 Xray 进程 (PID: {xray_process.pid}) 时发生错误: {e}", exc_info=True)

async def test_node(node_link, node_name):
    node_info = parse_node_info(node_link)
    if not node_info:
        logger.warning(f"节点 {node_name} 链接格式不支持或解析失败，跳过测试。")
        return {"node_info": {"remark": node_name, "original_link": node_link}, "status": "不支持的格式", "delay": -1}

    # 优先使用备注作为节点名称
    display_name = node_info.get("remark", node_name)
    node_info["original_link"] = node_link # 将原始链接添加到node_info

    # 如果地址是域名，进行 DNS 解析并替换为 IP
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", node_info["address"]):
        resolved_ip = await resolve_dns(node_info["address"])
        if resolved_ip:
            node_info["address"] = resolved_ip
        else:
            logger.warning(f"节点 {display_name} ({node_info['address']}) DNS 解析失败，跳过测试。")
            return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "DNS解析失败", "delay": -1}

    config_content = generate_xray_config(node_info)
    if not config_content:
        logger.warning(f"节点 {display_name} 无法生成 Xray 配置，跳过测试。")
        return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "配置生成失败", "delay": -1}

    xray_process = None
    try:
        xray_process, proxy_url = await start_proxy_subprocess(config_content)
        if xray_process is None or proxy_url is None: # 检查是否成功启动
            logger.warning(f"节点 {display_name} Xray 启动失败，跳过测试。")
            return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "Xray启动失败", "delay": -1}

        is_connected, result_info = await check_connectivity(proxy_url)

        if is_connected:
            logger.info(f"节点 {display_name} 测试成功, 延迟: {result_info} ms")
            return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "成功", "delay": result_info}
        else:
            logger.warning(f"节点 {display_name} 测试失败: {result_info}")
            return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "失败", "delay": -1, "error": result_info}
    except Exception as e:
        logger.error(f"测试节点 {display_name} 时发生异常: {e}", exc_info=True)
        return {"node_info": {"remark": display_name, "original_link": node_link}, "status": "异常", "delay": -1, "error": str(e)}
    finally:
        await terminate_xray_process(xray_process)

async def load_history():
    global history_results
    if os.path.exists(HISTORY_FILE):
        async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
            try:
                history_results = json.loads(await f.read())
                # 过滤过期历史记录
                current_time = time.time()
                history_results = {
                    link: data for link, data in history_results.items()
                    if (current_time - data.get("timestamp", 0) < HISTORY_EXPIRATION)
                }
                logger.info(f"已加载 {len(history_results)} 条历史记录。")
            except json.JSONDecodeError:
                logger.warning("历史记录文件损坏，重新创建。")
                history_results = {}
    else:
        history_results = {}

async def save_history():
    # 确保保存的节点包含原始链接
    for link, data in history_results.items():
        if "original_link" not in data.get("node_info", {}):
            node_info = parse_node_info(link)
            if node_info:
                history_results[link]["node_info"]["original_link"] = link
    
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
                # 过滤过期缓存
                current_time = time.time()
                dns_cache = {
                    hostname: data for hostname, data in dns_cache.items()
                    if (current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION)
                }
                logger.info(f"已加载 {len(dns_cache)} 条 DNS 缓存。")
            except json.JSONDecodeError:
                logger.warning("DNS 缓存文件损坏，重新创建。")
                dns_cache = {}
    else:
        dns_cache = {}

async def save_dns_cache():
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(dns_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS 缓存已保存: {len(dns_cache)} 条记录")

async def fetch_subscription_links(url):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
            response.raise_for_status()
            content = response.text
            # 尝试解码 base64
            try:
                decoded_content = base64.b64decode(content).decode('utf-8')
                return decoded_content.splitlines()
            except Exception:
                # 如果不是 base64，直接按行分割
                return content.splitlines()
    except httpx.RequestError as e:
        logger.error(f"获取订阅链接失败 {url}: {e}")
        return []

async def get_all_nodes():
    all_links = []
    for url in SOURCE_URLS:
        links = await fetch_subscription_links(url)
        all_links.extend(links)
    
    unique_nodes = {}
    for link in all_links:
        parsed = parse_node_info(link)
        if parsed and parsed.get("remark"):
            # 使用 remark 和 type 作为唯一标识，避免重复添加
            unique_key = f"{parsed['remark']}_{parsed['type']}"
            if unique_key not in unique_nodes:
                unique_nodes[unique_key] = link
    return list(unique_nodes.values())

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
    logger.info(f"共获取到 {len(all_nodes_links)} 个节点链接。")

    test_results = []
    successful_nodes = []

    # 过滤掉近期已成功且仍在历史记录中的节点
    nodes_to_test = []
    for link in all_nodes_links:
        if link in history_results and history_results[link].get("status") == "成功" and \
           (time.time() - history_results[link].get("timestamp", 0) < HISTORY_EXPIRATION):
            logger.info(f"节点 {history_results[link]['node_info']['remark']} 近期已成功，跳过测试。")
            test_results.append(history_results[link])
            successful_nodes.append(history_results[link])
        else:
            nodes_to_test.append(link)

    logger.info(f"实际需要测试 {len(nodes_to_test)} 个节点。")

    # 分批测试
    for i in range(0, len(nodes_to_test), BATCH_SIZE):
        batch = nodes_to_test[i:i + BATCH_SIZE]
        logger.info(f"正在测试批次 {i // BATCH_SIZE + 1}/{len(nodes_to_test) // BATCH_SIZE + (1 if len(nodes_to_test) % BATCH_SIZE else 0)}，已处理 {i}/{len(nodes_to_test)} 节点")
        tasks = [test_node(link, f"节点 {i+j+1}") for j, link in enumerate(batch)]
        
        batch_results = await asyncio.gather(*tasks)
        test_results.extend(batch_results)

        for result in batch_results:
            if result["status"] == "成功":
                successful_nodes.append(result)
            # 更新历史记录
            original_link = result["node_info"]["original_link"]
            history_results[original_link] = {
                "node_info": result["node_info"],
                "status": result["status"],
                "delay": result["delay"],
                "timestamp": time.time(),
                "error": result.get("error")
            }

    # 按延迟排序成功的节点
    successful_nodes.sort(key=lambda x: x["delay"])

    # 输出到文件
    async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_nodes:
            for result in successful_nodes:
                await f.write(f"{result['node_info']['original_link']}\n")
        else:
            await f.write("# 无可用节点\n")

    async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
        await f.write(str(len(successful_nodes)))

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

    print(f"最终成功节点数: {len(successful_nodes)}")
    logger.info(f"总耗时: {time.time() - start_time:.2f} 秒")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"脚本执行失败: {e}", exc_info=True)
        async def write_error_files():
            os.makedirs(DATA_DIR, exist_ok=True)
            async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
                await f.write("# 脚本执行失败，无可用节点\n")
            async with aiofiles.open(SUCCESS_COUNT_FILE, "w", encoding="utf-8") as f:
                await f.write("0")
        asyncio.run(write_error_files())
