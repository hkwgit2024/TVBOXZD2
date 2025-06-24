import httpx
import asyncio
import re
import os
import base64
from urllib.parse import urlparse, unquote, parse_qs
from typing import Union # 导入 Union

# 配置
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/sub.txt"
TIMEOUT = 10  # 秒
CONCURRENCY_LIMIT = 50  # 并发测试的节点数量

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
                print(f"解析行失败: {line[:50]}... 错误: SSR base64 解码失败")
                return None

            parts = decoded_part.split(':')
            if len(parts) < 6: # server:port:protocol:method:obfs:password
                print(f"解析行失败: {line[:50]}... 错误: SSR 格式不完整")
                return None
            
            server = parts[0]
            port = int(parts[1])
            # protocol = parts[2]
            # method = parts[3]
            # obfs = parts[4]
            # password = safe_base64_decode(parts[5].split('/')[0]) # password可能后面跟/
            remark = safe_base64_decode(encoded_remark) if encoded_remark else f"Unnamed SSR Node"

            return {
                "protocol": "ssr",
                "server": server,
                "port": port,
                "remark": remark,
                "original_link": line
            }
        elif line.startswith("vless://") or line.startswith("vmess://") or line.startswith("trojan://"):
            # 对于 IPv6 地址，urllib.parse 应该能处理方括号，但可能出现不规范的连接方式
            # 比如 trojan://user@[ipv6]:port?key=value，如果没有端口号或者格式不规范，urllib.parse可能会有问题
            # 这里依赖urlparse的健壮性，如果报错，再考虑正则捕获
            parsed_url = urlparse(line)
            
            # 检查 hostname 是否有效，特别是对于 IPv6
            if not parsed_url.hostname:
                # 尝试更宽松的IPv6匹配
                match = re.match(r"^(.*?)(?:\[([0-9a-fA-F:]+)\]):?(\d+)?(.*)", line)
                if match:
                    protocol_prefix, ipv6_addr, port_str, remainder = match.groups()
                    if ipv6_addr:
                        server = f"[{ipv6_addr}]"
                        port = int(port_str) if port_str else None
                        # 重构一个有效的URL用于进一步解析查询参数和 fragment
                        temp_url = f"{protocol_prefix}{server}:{port}{remainder}"
                        parsed_url = urlparse(temp_url)
                    else:
                        raise ValueError("Invalid IPv6 URL format (missing address)")
                else:
                    raise ValueError(f"Invalid URL: {line}")


            protocol = parsed_url.scheme
            server = parsed_url.hostname # 如果是IPv6，这里会是带方括号的
            port = parsed_url.port
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else f"Unnamed {protocol.upper()} Node"

            # 提取查询参数（例如VLESS的security, type, sni, path）
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
            # hysteria2://uuid@server:port?params#remark
            parsed_url = urlparse(line)
            
            if not parsed_url.hostname:
                 match = re.match(r"^(.*?)(?:\[([0-9a-fA-F:]+)\]):?(\d+)?(.*)", line)
                 if match:
                     protocol_prefix, ipv6_addr, port_str, remainder = match.groups()
                     if ipv6_addr:
                         server = f"[{ipv6_addr}]"
                         port = int(port_str) if port_str else None
                         temp_url = f"{protocol_prefix}{server}:{port}{remainder}"
                         parsed_url = urlparse(temp_url)
                     else:
                         raise ValueError("Invalid IPv6 URL format (missing address)")
                 else:
                     raise ValueError(f"Invalid URL: {line}")

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
            print(f"无法识别的协议或格式: {line.split('://')[0] if '://' in line else line[:20]}...")
            return None
    except Exception as e:
        print(f"解析行失败: {line[:50]}... 错误: {e}")
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
        # 对于所有协议，我们首先尝试建立一个裸TCP连接
        # 这可以检查端口是否开放，以及基本的网络可达性
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port), timeout=TIMEOUT
        )
        # 发送一个小的 HTTP GET 请求以探测，并尽快关闭
        # 注意：这只是一个通用探测，代理服务器可能不会响应标准的HTTP请求
        # 但它有助于检查TLS握手是否至少开始。
        if protocol in ["vless", "vmess", "trojan", "hysteria2"] and node.get("security") == "tls":
            # 对于TLS连接，尝试发送ClientHello，不期待完整HTTP响应
            # 这比裸TCP连接更进一步，但仍不是完整协议实现
            # 更完善的TLS握手验证需要ssl模块或专业库
            # 简单发送一些数据，如果TLS握手失败，ConnectionResetError等会捕获
            await writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        else:
            # 对于非TLS的简单TCP连接
            await writer.write(b"Hello\r\n") # 发送一些无害数据

        await writer.drain() # 确保数据发送
        
        # 尝试读取一些响应，但不阻塞太久
        try:
            # 100字节的简单读取，避免长时间等待
            await asyncio.wait_for(reader.read(100), timeout=1) 
        except asyncio.TimeoutError:
            pass # 可能是代理服务器不响应或非HTTP服务，不是致命错误

        writer.close()
        await reader.wait_closed() # 等待关闭，确保连接完成

        end_time = asyncio.get_event_loop().time()
        latency_ms = round((end_time - start_time) * 1000)
        status = "Success"
        error_msg = ""

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, httpx.RequestError) as e:
        error_msg = str(e)
        status = "Failed"
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        status = "Failed"

    print(f"测试 {remark} ({server}:{port}) - 状态: {status}, 延迟: {latency_ms}ms, 错误: {error_msg}")
    return {
        "node": node,
        "status": status,
        "latency_ms": latency_ms,
        "error": error_msg,
        "original_link": original_link
    }

async def main():
    """主函数，负责下载、解析和并发测试节点"""
    # 确保 data 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        print("无法获取节点列表，退出。")
        return

    lines = ss_txt_content.splitlines()
    
    # 解析所有节点
    parsed_nodes = []
    for line_num, line in enumerate(lines):
        node = parse_node_info(line)
        if node:
            parsed_nodes.append(node)
    
    nodes_to_test = parsed_nodes # 所有成功解析的节点

    print(f"成功解析到 {len(nodes_to_test)} 个有效节点，开始并发测试...")

    if not nodes_to_test:
        print("未解析到任何有效节点，退出。")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("No valid nodes found or tested.\n")
        return

    results = []
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def run_test(node):
        async with semaphore:
            return await test_node(node)

    tasks = [run_test(node) for node in nodes_to_test]
    tested_results = await asyncio.gather(*tasks)

    # 排序：成功的节点优先，按延迟升序；失败的节点在后
    tested_results.sort(key=lambda x: (x["status"] != "Success", x["latency_ms"] if x["status"] == "Success" else float('inf')))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# 节点测试结果 (连通性测试)\n")
        f.write(f"# 测试时间: {asyncio.get_event_loop().time()}\n\n")
        f.write(f"总计尝试测试节点数: {len(nodes_to_test)}\n")
        f.write(f"成功连接节点数: {sum(1 for r in tested_results if r['status'] == 'Success')}\n")
        f.write(f"失败连接节点数: {sum(1 for r in tested_results if r['status'] != 'Success')}\n\n")

        f.write("| 协议 | 备注 | 服务器 | 端口 | 状态 | 延迟 (ms) | 错误信息 | 原始链接 |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")

        for res in tested_results:
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
        for res in tested_results:
            if res["status"] == "Success":
                f.write(f"{res['original_link']}\n")

    print(f"测试完成。结果已保存到 {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
