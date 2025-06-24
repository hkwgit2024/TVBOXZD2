import httpx
import asyncio
import re
import os
from urllib.parse import urlparse, unquote, parse_qs

# 配置
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
OUTPUT_FILE = "data/sub.txt"
TIMEOUT = 10  # 秒
CONCURRENCY_LIMIT = 50  # 并发测试的节点数量

# 简单的正则匹配，用于提取SS/SSR节点信息
# 这是一个简化的示例，实际解析需要更健壮的逻辑
SS_SSR_RE = re.compile(r"ss://([^@]+?)@([^:]+?):(\d+)(?:/(.*))?#?(.*)")

async def fetch_ss_txt(url: str) -> str:
    """从URL下载ss.txt文件内容"""
    print(f"正在从 {url} 下载节点列表...")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()  # 检查HTTP错误
            print("节点列表下载成功。")
            return response.text
        except httpx.HTTPStatusError as e:
            print(f"HTTP错误下载文件: {e.response.status_code} - {e.response.text}")
            return ""
        except httpx.RequestError as e:
            print(f"请求错误下载文件: {e}")
            return ""

def parse_node_info(line: str) -> dict | None:
    """
    解析一行节点信息，支持 ss, vless, trojan 协议。
    仅提取关键信息，不进行完整协议解析。
    """
    line = line.strip()
    if not line:
        return None

    try:
        if line.startswith("ss://"):
            parsed_url = urlparse(line)
            # SS/SSR 比较特殊，它的UserInfo部分需要base64解码，然后解析
            # 这里我们尝试简单地提取，更复杂的需要额外解码逻辑
            # 例如 ss://base64(method:password)@server:port#name
            # simplified_match = SS_SSR_RE.match(line)
            # if simplified_match:
            #     encoded_info = simplified_match.group(1)
            #     try:
            #         # 尝试解码，但SS/SSR编码方式多样，这里可能不通用
            #         decoded_info = base64.urlsafe_b64decode(encoded_info + '==').decode('utf-8')
            #         method_pass = decoded_info.split(':')
            #         method = method_pass[0] if len(method_pass) > 0 else 'unknown'
            #         password = method_pass[1] if len(method_pass) > 1 else ''
            #     except Exception:
            #         method = 'unknown'
            #         password = ''
            #     server = simplified_match.group(2)
            #     port = int(simplified_match.group(3))
            #     remark = unquote(simplified_match.group(5) or 'Unnamed SS')
            #     return {
            #         "protocol": "ss",
            #         "server": server,
            #         "port": port,
            #         "method": method,
            #         "password": password,
            #         "remark": remark,
            #         "original_link": line
            #     }
            # 为了简化和通用性，我们直接提取host和port
            return {
                "protocol": "ss",
                "server": parsed_url.hostname,
                "port": parsed_url.port,
                "remark": unquote(parsed_url.fragment) if parsed_url.fragment else f"Unnamed SS Node",
                "original_link": line
            }
        elif line.startswith("vless://") or line.startswith("vmess://") or line.startswith("trojan://"):
            parsed_url = urlparse(line)
            protocol = parsed_url.scheme
            server = parsed_url.hostname
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
        else:
            print(f"无法识别的协议或格式: {line[:50]}...")
            return None
    except Exception as e:
        print(f"解析行失败: {line[:50]}... 错误: {e}")
        return None

async def test_node(node: dict) -> dict:
    """
    尝试测试一个节点的可达性。
    这里的测试非常基础，仅尝试建立TCP连接或通过HTTP/HTTPS探测。
    对于VLESS/Trojan的TLS/WS/XTLS等特性，这里无法完全模拟。
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

    start_time = asyncio.get_event_loop().time()
    try:
        # 对于所有协议，我们首先尝试建立一个裸TCP连接
        # 这可以检查端口是否开放，以及基本的网络可达性
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, port), timeout=TIMEOUT
        )
        writer.close()
        await reader.wait_closed() # 等待关闭，确保连接完成

        # 进一步的测试（可选）：
        # 对于支持TLS的协议（vless, trojan, ss-tls），可以尝试TLS握手。
        # 但这需要更复杂的客户端模拟。
        # 这里为了简化，仅判断TCP连接成功。
        
        # 也可以尝试简单的HTTP请求，但通常代理不直接是HTTP服务器
        # async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        #     # 尝试通过节点直接访问一个公共网站（不通过代理设置，只是测试节点本身是否响应HTTP）
        #     # 这通常不适用于代理节点，因为它们不是HTTP服务器
        #     # response = await client.get(f"http://{server}:{port}/", follow_redirects=False)
        #     # response.raise_for_status()
        #     pass # 仅 TCP 连接测试

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

    print(f"测试 {remark} ({server}:{port}) - 状态: {status}, 延迟: {latency_ms}ms")
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
    nodes_to_test = [parse_node_info(line) for line in lines]
    nodes_to_test = [node for node in nodes_to_test if node] # 过滤掉解析失败的节点

    if not nodes_to_test:
        print("未解析到任何有效节点，退出。")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("No valid nodes found or tested.\n")
        return

    print(f"总计解析到 {len(nodes_to_test)} 个节点，开始并发测试...")

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
        f.write("# 节点测试结果 (仅连通性测试)\n")
        f.write(f"# 测试时间: {asyncio.get_event_loop().time()}\n\n")
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
