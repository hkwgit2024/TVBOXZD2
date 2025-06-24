import httpx
import asyncio
import re
import os
import base64
from urllib.parse import urlparse, unquote, parse_qs
from typing import Union, Dict, Any
import logging
import json
import socket # 引入 socket 模块用于 DNS 预解析

# --- 配置 ---
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/sub.txt"
HISTORY_FILE = "data/history_results.json" # 保存历史测试结果的文件
DNS_CACHE_FILE = "data/dns_cache.json" # DNS 缓存文件
TIMEOUT_FETCH = 15 # 下载文件超时
TIMEOUT_NODE_CONNECT = 8 # 单个节点连接超时
CONCURRENCY_LIMIT = 100 # 并发测试的节点数量

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO, # 默认信息级别，可以改为 DEBUG 查看更详细信息
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler() # 输出到控制台
    ]
)
logger = logging.getLogger(__name__)

# 全局 DNS 缓存
dns_cache: Dict[str, str] = {}

# --- 辅助函数 ---
def safe_base64_decode(s: str) -> str:
    """尝试解码 base64 字符串，处理 URL 安全和填充问题"""
    s = s.replace('-', '+').replace('_', '/')
    padding_needed = len(s) % 4
    if padding_needed:
        s += '=' * (4 - padding_needed)
    try:
        return base64.b64decode(s).decode('utf-8')
    except Exception:
        return ""

async def fetch_ss_txt(url: str) -> str:
    """从URL下载ss.txt文件内容"""
    logger.info(f"正在从 {url} 下载节点列表...")
    async with httpx.AsyncClient(timeout=TIMEOUT_FETCH) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            logger.info("节点列表下载成功。")
            return response.text
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP错误下载文件: {e.response.status_code} - {e.response.text}")
            return ""
        except httpx.RequestError as e:
            logger.error(f"请求错误下载文件: {e}")
            return ""

def parse_node_info(line: str) -> Union[Dict[str, Any], None]:
    """解析一行节点信息"""
    line = line.strip()
    if not line:
        return None

    try:
        if line.startswith("ss://"):
            parsed_url = urlparse(line)
            if not parsed_url.hostname or not parsed_url.port:
                logger.debug(f"解析行失败: {line[:50]}... 错误: SS 节点缺少主机或端口")
                return None
            return {
                "protocol": "ss",
                "server": parsed_url.hostname,
                "port": parsed_url.port,
                "remark": unquote(parsed_url.fragment) if parsed_url.fragment else f"Unnamed SS Node",
                "original_link": line
            }
        elif line.startswith("ssr://"):
            encoded_part = line[len("ssr://"):]
            if '#' in encoded_part:
                encoded_part, encoded_remark = encoded_part.split('#', 1)
            else:
                encoded_remark = ""

            decoded_part = safe_base64_decode(encoded_part)
            if not decoded_part:
                logger.debug(f"解析行失败: {line[:50]}... 错误: SSR base64 解码失败")
                return None

            parts = decoded_part.split(':')
            if len(parts) < 6:
                logger.debug(f"解析行失败: {line[:50]}... 错误: SSR 格式不完整")
                return None
            
            server = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                logger.debug(f"解析行失败: {line[:50]}... 错误: SSR 端口无效")
                return None
            
            remark = safe_base64_decode(encoded_remark) if encoded_remark else f"Unnamed SSR Node"

            return {
                "protocol": "ssr",
                "server": server,
                "port": port,
                "remark": remark,
                "original_link": line
            }
        elif line.startswith("vless://") or line.startswith("vmess://") or line.startswith("trojan://"):
            parsed_url = urlparse(line)
            
            if not parsed_url.hostname or not parsed_url.port:
                match = re.match(r"^(.*?)(?:\[([0-9a-fA-F.:]+)\]):?(\d+)?(.*)", line)
                if match:
                    protocol_prefix, ipv6_addr, port_str, remainder = match.groups()
                    if ipv6_addr:
                        server = f"[{ipv6_addr}]"
                        try:
                            port = int(port_str) if port_str else None
                        except ValueError:
                            logger.debug(f"解析行失败: {line[:50]}... 错误: {protocol_prefix} 端口无效")
                            return None
                        
                        temp_url = f"{protocol_prefix}{server}:{port}{remainder}"
                        parsed_url = urlparse(temp_url)
                    else:
                        logger.debug(f"解析行失败: {line[:50]}... 错误: Invalid IPv6 URL format (missing address)")
                        return None
                else:
                    logger.debug(f"解析行失败: {line[:50]}... 错误: URL 格式不正确或缺少主机/端口")
                    return None

            protocol = parsed_url.scheme
            server = parsed_url.hostname
            port = parsed_url.port
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else f"Unnamed {protocol.upper()} Node"

            query_params = parse_qs(parsed_url.query)
            
            return {
                "protocol": protocol,
                "server": server,
                "port": port,
                "remark": remark,
                "security": query_params.get('security', [''])[0],
                "type": query_params.get('type', [''])[0],
                "sni": query_params.get('sni', [''])[0],
                "path": query_params.get('path', [''])[0],
                "original_link": line
            }
        elif line.startswith("hysteria2://"):
            parsed_url = urlparse(line)
            
            if not parsed_url.hostname or not parsed_url.port:
                 match = re.match(r"^(.*?)(?:\[([0-9a-fA-F.:]+)\]):?(\d+)?(.*)", line)
                 if match:
                     protocol_prefix, ipv6_addr, port_str, remainder = match.groups()
                     if ipv6_addr:
                         server = f"[{ipv6_addr}]"
                         try:
                             port = int(port_str) if port_str else None
                         except ValueError:
                            logger.debug(f"解析行失败: {line[:50]}... 错误: Hysteria2 端口无效")
                            return None

                         temp_url = f"{protocol_prefix}{server}:{port}{remainder}"
                         parsed_url = urlparse(temp_url)
                     else:
                         logger.debug(f"解析行失败: {line[:50]}... 错误: Invalid IPv6 URL format (missing address)")
                         return None
                 else:
                     logger.debug(f"解析行失败: {line[:50]}... 错误: Hysteria2 URL 格式不正确或缺少主机/端口")
                     return None

            protocol = parsed_url.scheme
            server = parsed_url.hostname
            port = parsed_url.port
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else "Unnamed Hysteria2 Node"
            query_params = parse_qs(parsed_url.query)

            return {
                "protocol": protocol,
                "server": server,
                "port": port,
                "remark": remark,
                "auth": unquote(parsed_url.username) if parsed_url.username else '',
                "fastopen": query_params.get('fastopen', [''])[0],
                "obfs": query_params.get('obfs', [''])[0],
                "obfsParam": query_params.get('obfsParam', [''])[0],
                "peer": query_params.get('peer', [''])[0],
                "up": query_params.get('up', [''])[0],
                "down": query_params.get('down', [''])[0],
                "original_link": line
            }
        else:
            logger.debug(f"无法识别的协议或格式: {line.split('://')[0] if '://' in line else line[:20]}...")
            return None
    except Exception as e:
        logger.debug(f"解析行失败: {line[:50]}... 错误: {e}")
        return None

async def dns_lookup(hostname: str) -> Union[str, None]:
    """执行 DNS 预解析，并使用缓存"""
    global dns_cache # 声明使用全局变量

    if hostname.startswith('[') and hostname.endswith(']'): # IPv6 literal
        return hostname.strip('[]')
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname): # IPv4 literal
        return hostname
    
    # 检查缓存
    if hostname in dns_cache:
        logger.debug(f"从 DNS 缓存获取 {hostname}: {dns_cache[hostname]}")
        return dns_cache[hostname]

    try:
        info = await asyncio.get_event_loop().getaddrinfo(hostname, None, family=0, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        if info:
            resolved_ip = info[0][4][0]
            dns_cache[hostname] = resolved_ip # 存入缓存
            logger.debug(f"DNS 解析成功并缓存 {hostname}: {resolved_ip}")
            return resolved_ip
        return None
    except socket.gaierror as e:
        logger.debug(f"DNS 解析失败 for {hostname}: {e}")
        return None
    except Exception as e:
        logger.debug(f"DNS 解析时发生未知错误 for {hostname}: {e}")
        return None

async def test_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """
    尝试测试一个节点的可达性，并增加 DNS 预解析。
    """
    protocol = node.get("protocol")
    server = node.get("server")
    port = node.get("port")
    remark = node.get("remark", "Unnamed Node")
    original_link = node.get("original_link", "N/A")

    result = {
        "node": node,
        "status": "Failed",
        "latency_ms": -1,
        "error": "Unknown Error",
        "original_link": original_link
    }

    if not server or not port:
        result["status"] = "Invalid Node Info"
        result["error"] = "Server or Port Missing"
        logger.debug(f"跳过无效节点 (缺少服务器或端口): {original_link}")
        return result

    # --- DNS 预解析 ---
    connect_host = server
    if not (server.startswith('[') and server.endswith(']') or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server)):
        # 如果不是 IP 地址，则进行 DNS 解析
        resolved_ip = await dns_lookup(server)
        if not resolved_ip:
            result["status"] = "DNS Resolution Failed"
            result["error"] = f"DNS Resolution Failed for {server}"
            logger.info(f"测试 {remark} ({server}:{port}) - 状态: {result['status']}, 错误: {result['error']}")
            return result
        connect_host = resolved_ip
        node['resolved_ip'] = resolved_ip # 记录解析到的IP，可选

    start_time = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port), timeout=TIMEOUT_NODE_CONNECT
        )
        
        try:
            if protocol in ["vless", "vmess", "trojan"] and node.get("security") == "tls":
                await writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            elif protocol == "hysteria2":
                await writer.write(b"H2CONNECT / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            else:
                await writer.write(b"Hello\r\n")

            await writer.drain()
            await asyncio.wait_for(reader.read(100), timeout=1) 
        except asyncio.TimeoutError:
            pass 
        except Exception as read_error:
            logger.debug(f"读取响应时发生错误: {read_error}")
            pass

        writer.close()
        await reader.wait_closed()

        end_time = asyncio.get_event_loop().time()
        result["latency_ms"] = round((end_time - start_time) * 1000)
        result["status"] = "Success"
        result["error"] = ""

    except asyncio.TimeoutError:
        result["error"] = "Connection Timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection Refused"
    except OSError as e:
        result["error"] = str(e)
    except httpx.RequestError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"

    if result["status"] == "Failed" or logger.level <= logging.DEBUG:
        logger.info(f"测试 {remark} ({server}:{port}) - 状态: {result['status']}, 延迟: {result['latency_ms']}ms, 错误: {result['error']}")
    else:
        logger.info(f"测试 {remark} ({server}:{port}) - 状态: {result['status']}, 延迟: {result['latency_ms']}ms")
        
    return result

def load_history_results(file_path: str) -> Dict[str, Dict[str, Any]]:
    """从文件中加载历史测试结果"""
    history_map = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    # 使用 original_link 作为唯一键
                    history_map[item.get("original_link")] = item
            logger.info(f"加载了 {len(history_map)} 条历史测试结果。")
        except json.JSONDecodeError as e:
            logger.warning(f"历史结果文件 {file_path} 解析失败: {e}，将忽略历史数据。")
        except Exception as e:
            logger.warning(f"加载历史结果文件 {file_path} 时发生未知错误: {e}，将忽略历史数据。")
    return history_map

def save_history_results(file_path: str, results: list):
    """将当前测试结果保存到文件，用于下次运行"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        logger.info(f"已将 {len(results)} 条测试结果保存到 {file_path}")
    except Exception as e:
        logger.error(f"保存历史结果到文件 {file_path} 失败: {e}")

def load_dns_cache(file_path: str) -> Dict[str, str]:
    """从文件中加载 DNS 缓存"""
    cache = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
            logger.info(f"加载了 {len(cache)} 条 DNS 缓存记录。")
        except json.JSONDecodeError as e:
            logger.warning(f"DNS 缓存文件 {file_path} 解析失败: {e}，将忽略缓存。")
        except Exception as e:
            logger.warning(f"加载 DNS 缓存文件 {file_path} 时发生未知错误: {e}，将忽略缓存。")
    return cache

def save_dns_cache(file_path: str, cache: Dict[str, str]):
    """将 DNS 缓存保存到文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        logger.info(f"已将 {len(cache)} 条 DNS 缓存记录保存到 {file_path}")
    except Exception as e:
        logger.error(f"保存 DNS 缓存到文件 {file_path} 失败: {e}")

async def main():
    """主函数，负责下载、解析、对比历史数据、并发测试节点"""
    global dns_cache # 声明使用全局变量

    logger.info("程序开始运行。")
    
    # 确保 data 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # 1. 加载历史测试结果和 DNS 缓存
    history_results_map = load_history_results(HISTORY_FILE)
    dns_cache = load_dns_cache(DNS_CACHE_FILE)

    # 2. 下载新的节点列表
    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        logger.error("无法获取节点列表，退出。")
        return

    lines = ss_txt_content.splitlines()
    total_lines = len(lines)
    logger.info(f"成功下载 {total_lines} 行原始节点数据。")

    # 3. 解析所有节点，并准备测试列表
    current_parsed_nodes = []
    nodes_to_test_now = [] # 需要进行网络测试的节点
    tested_results_from_history = [] # 直接使用历史结果的节点

    for line_num, line in enumerate(lines):
        node = parse_node_info(line)
        if node:
            current_parsed_nodes.append(node)
            original_link = node.get("original_link")
            
            # 检查节点是否在历史记录中，并且上次是失败的
            if original_link in history_results_map:
                history_res = history_results_map[original_link]
                # 如果上次测试是失败的，且链接完全相同，则跳过本次网络测试
                # 可以根据需要调整跳过逻辑，例如只跳过特定错误类型的
                if history_res.get("status") in ["Failed", "DNS Resolution Failed", "Invalid Node Info"]:
                    # 重新封装历史结果，以符合当前结果格式
                    reused_result = {
                        "node": node, # 使用当前解析的节点信息
                        "status": history_res.get("status", "Failed (Cached)"),
                        "latency_ms": history_res.get("latency_ms", -1),
                        "error": history_res.get("error", "Skipped (previously failed)"),
                        "original_link": original_link
                    }
                    tested_results_from_history.append(reused_result)
                    logger.debug(f"跳过已知的失败节点 (历史记录): {node.get('remark')}")
                    continue # 跳过网络测试

            nodes_to_test_now.append(node) # 需要测试的节点

    logger.info(f"总计解析到 {len(current_parsed_nodes)} 个有效节点。")
    logger.info(f"其中 {len(tested_results_from_history)} 个节点从历史记录中跳过，{len(nodes_to_test_now)} 个节点将进行网络测试。")

    if not current_parsed_nodes:
        logger.warning("未解析到任何有效节点，退出。")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("No valid nodes found or tested.\n")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def run_test(node_to_test):
        async with semaphore:
            return await test_node(node_to_test)

    tasks = [run_test(node) for node in nodes_to_test_now]
    tested_results_live = await asyncio.gather(*tasks)

    # 合并所有结果
    all_results = tested_results_from_history + tested_results_live

    # 4. 排序和保存结果
    # 排序：成功的节点优先，按延迟升序；失败的节点在后
    all_results.sort(key=lambda x: (x["status"] != "Success", x["latency_ms"] if x["status"] == "Success" else float('inf')))

    successful_nodes_count = sum(1 for r in all_results if r['status'] == 'Success')
    failed_nodes_count = sum(1 for r in all_results if r['status'] != 'Success')

    logger.info(f"测试完成。成功连接节点数: {successful_nodes_count}, 失败连接节点数: {failed_nodes_count}")
    logger.info(f"结果已保存到 {OUTPUT_FILE}")

    # 将所有结果保存到历史文件
    save_history_results(HISTORY_FILE, all_results)
    # 保存 DNS 缓存
    save_dns_cache(DNS_CACHE_FILE, dns_cache)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# 节点测试结果 (连通性测试)\n")
        f.write(f"# 测试时间: {asyncio.get_event_loop().time()}\n\n")
        f.write(f"总计解析节点数: {len(current_parsed_nodes)}\n")
        f.write(f"实际进行网络测试节点数: {len(nodes_to_test_now)}\n")
        f.write(f"成功连接节点数: {successful_nodes_count}\n")
        f.write(f"失败连接节点数: {failed_nodes_count}\n\n")

        f.write("| 协议 | 备注 | 服务器 | 端口 | 状态 | 延迟 (ms) | 错误信息 | 原始链接 |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")

        for res in all_results:
            node = res["node"]
            status = res["status"]
            latency = res["latency_ms"] if res["latency_ms"] != -1 else "N/A"
            error = res["error"] if res["error"] else ""
            original_link = res["original_link"]
            
            f.write(
                f"| {node.get('protocol', 'N/A')} "
                f"| {node.get('remark', 'N/A')} "
                f"| {node.get('server', 'N/A')} "
                f"| {node.get('port', 'N/A')} "
                f"| {status} "
                f"| {latency} "
                f"| {error} "
                f"| `{original_link}` |\n"
            )
        f.write("\n# 可用节点 (仅显示测试成功的节点)\n")
        for res in all_results:
            if res["status"] == "Success":
                f.write(f"{res['original_link']}\n")

if __name__ == "__main__":
    asyncio.run(main())
