import httpx
import asyncio
import re
import os
import base64
from urllib.parse import urlparse, unquote, parse_qs
from typing import Union
import logging # 引入日志模块

# 配置
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/sub.txt"
TIMEOUT_FETCH = 15 # 下载文件超时
TIMEOUT_NODE_CONNECT = 8 # 单个节点连接超时（降低）
CONCURRENCY_LIMIT = 100 # 并发测试的节点数量（适当提高）

# 配置日志
logging.basicConfig(
    level=logging.INFO, # 默认信息级别，可以改为 DEBUG 查看更详细信息
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler() # 输出到控制台
        # logging.FileHandler("test_log.log") # 如果需要保存到文件
    ]
)
logger = logging.getLogger(__name__)

# 辅助函数：尝试解码 base64 并处理 URL 安全编码
def safe_base64_decode(s: str) -> str:
    """尝试解码 base64 字符串，处理 URL 安全和填充问题"""
    s = s.replace('-', '+').replace('_', '/') # URL 安全到标准
    # 添加填充，直到长度是4的倍数
    padding_needed = len(s) % 4
    if padding_needed:
        s += '=' * (4 - padding_needed)
    try:
        return base64.b64decode(s).decode('utf-8')
    except Exception:
        return ""

def parse_node_info(line: str) -> Union[dict, None]:
    """
    解析一行节点信息，支持 ss, ssr, vless, vmess, trojan, hysteria2 协议。
    仅提取关键信息，不进行完整协议解析。
    """
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
            # SSR 格式比较特殊：ssr://base64(server:port:protocol:method:obfs:password_base64/?params)#remark_base64
            # 简化解析：只提取关键部分
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
            if len(parts) < 6: # server:port:protocol:method:obfs:password
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
            
            # 尝试处理 IPv6 地址和不规范 URL
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
            server = parsed_url.hostname # 如果是IPv6，这里会是带方括号的
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
            # 打印前缀而不是整个行，避免日志过长
            logger.debug(f"无法识别的协议或格式: {line.split('://')[0] if '://' in line else line[:20]}...")
            return None
    except Exception as e:
        logger.debug(f"解析行失败: {line[:50]}... 错误: {e}")
        return None

async def test_node(node: dict) -> dict:
    """
    尝试测试一个节点的可达性。
    这里的测试非常基础，仅尝试建立TCP连接并发送少量数据。
    对于VLESS/Trojan/Hysteria2的TLS/WS/XTLS等特性，这里无法完全模拟。
    """
    protocol = node.get("protocol")
    server = node.get("server")
    port = node.get("port")
    remark = node.get("remark", "Unnamed Node")
    original_link = node.get("original_link", "N/A")

    if not server or not port:
        logger.debug(f"跳过无效节点 (缺少服务器或端口): {original_link}")
        return {
            "node": node,
            "status": "Invalid Node Info",
            "latency_ms": -1,
            "error": "Server or Port Missing",
            "original_link": original_link
        }

    status = "Failed"
    latency_ms = -1
    error_msg = "Unknown Error"

    # 处理 IPv6 地址，asyncio.open_connection 接受带方括号的 IPv6
    connect_host = server.strip('[]') if server.startswith('[') and server.endswith(']') else server

    start_time = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port), timeout=TIMEOUT_NODE_CONNECT
        )
        
        # 尝试发送一个小的 HTTP GET 请求以探测，并尽快关闭
        # 注意：这只是一个通用探测，代理服务器可能不会响应标准的HTTP请求
        # 但它有助于检查TLS握手是否至少开始。
        try:
            if protocol in ["vless", "vmess", "trojan"] and node.get("security") == "tls":
                # 尝试发送 ClientHello 模拟 TLS 握手启动
                # 这不是一个完整的 TLS 握手，只是探测连接是否能建立
                await writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            elif protocol == "hysteria2":
                 # Hysteria2 是 UDP 协议，但这里我们用 TCP 端口连通性作为初步判断
                 # 实际上，需要一个 Hysteria2 客户端才能真正测试
                await writer.write(b"H2CONNECT / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            else:
                await writer.write(b"Hello\r\n") # 发送一些无害数据

            await writer.drain() # 确保数据发送
            
            # 尝试读取一些响应，但不阻塞太久
            await asyncio.wait_for(reader.read(100), timeout=1) 
        except asyncio.TimeoutError:
            # 可能是代理服务器不响应或非HTTP服务，不是致命错误，继续关闭连接
            pass 
        except Exception as read_error:
            logger.debug(f"读取响应时发生错误: {read_error}")
            pass # 记录但不作为主要失败原因

        writer.close()
        await reader.wait_closed() # 等待关闭，确保连接完成

        end_time = asyncio.get_event_loop().time()
        latency_ms = round((end_time - start_time) * 1000)
        status = "Success"
        error_msg = ""

    except asyncio.TimeoutError:
        error_msg = "Connection Timeout"
        status = "Failed"
    except ConnectionRefusedError:
        error_msg = "Connection Refused"
        status = "Failed"
    except OSError as e:
        # 捕捉 Name or service not known (Errno -2) 等 DNS 或路由问题
        error_msg = str(e)
        status = "Failed"
    except httpx.RequestError as e: # httpx 如果在其他地方被用到的话
        error_msg = str(e)
        status = "Failed"
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        status = "Failed"

    # 仅在失败或DEBUG模式下打印详细信息
    if status == "Failed" or logger.level <= logging.DEBUG:
        logger.info(f"测试 {remark} ({server}:{port}) - 状态: {status}, 延迟: {latency_ms}ms, 错误: {error_msg}")
    else:
        logger.info(f"测试 {remark} ({server}:{port}) - 状态: {status}, 延迟: {latency_ms}ms")
        
    return {
        "node": node,
        "status": status,
        "latency_ms": latency_ms,
        "error": error_msg,
        "original_link": original_link
    }

async def main():
    """主函数，负责下载、解析和并发测试节点"""
    logger.info("程序开始运行。")
    # 确保 data 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        logger.error("无法获取节点列表，退出。")
        return

    lines = ss_txt_content.splitlines()
    total_lines = len(lines)
    logger.info(f"成功下载 {total_lines} 行原始节点数据。")

    # 解析所有节点
    parsed_nodes = []
    for line_num, line in enumerate(lines):
        node = parse_node_info(line)
        if node:
            parsed_nodes.append(node)
    
    nodes_to_test = parsed_nodes # 所有成功解析的节点
    
    logger.info(f"总计解析到 {len(nodes_to_test)} 个有效节点，开始并发测试...")

    if not nodes_to_test:
        logger.warning("未解析到任何有效节点，退出。")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("No valid nodes found or tested.\n")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def run_test(node):
        async with semaphore:
            return await test_node(node)

    tasks = [run_test(node) for node in nodes_to_test]
    tested_results = await asyncio.gather(*tasks)

    # 排序：成功的节点优先，按延迟升序；失败的节点在后
    tested_results.sort(key=lambda x: (x["status"] != "Success", x["latency_ms"] if x["status"] == "Success" else float('inf')))

    successful_nodes_count = sum(1 for r in tested_results if r['status'] == 'Success')
    failed_nodes_count = sum(1 for r in tested_results if r['status'] != 'Success')

    logger.info(f"测试完成。成功连接节点数: {successful_nodes_count}, 失败连接节点数: {failed_nodes_count}")
    logger.info(f"结果已保存到 {OUTPUT_FILE}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# 节点测试结果 (连通性测试)\n")
        f.write(f"# 测试时间: {asyncio.get_event_loop().time()}\n\n")
        f.write(f"总计尝试测试节点数: {len(nodes_to_test)}\n")
        f.write(f"成功连接节点数: {successful_nodes_count}\n")
        f.write(f"失败连接节点数: {failed_nodes_count}\n\n")

        f.write("| 协议 | 备注 | 服务器 | 端口 | 状态 | 延迟 (ms) | 错误信息 | 原始链接 |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")

        for res in tested_results:
            node = res["node"]
            status = res["status"]
            latency = res["latency_ms"] if res["latency_ms"] != -1 else "N/A"
            error = res["error"] if error else "" # 确保是空字符串
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
        for res in tested_results:
            if res["status"] == "Success":
                f.write(f"{res['original_link']}\n")

if __name__ == "__main__":
    asyncio.run(main())
