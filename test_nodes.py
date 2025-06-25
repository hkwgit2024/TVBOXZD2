import os
import re
import asyncio
import aiohttp
import json
import subprocess
import time

# 定义data目录和文件路径
DATA_DIR = "data"
SUB_FILE = os.path.join(DATA_DIR, "sub.txt")
ALL_FILE = os.path.join(DATA_DIR, "all.txt")

# 目标测试网站
TARGET_URL = "https://www.google.com" # 请替换为你想测试的网站，例如 "https://www.baidu.com"
TEST_TIMEOUT = 15 # 每个节点测试超时时间（秒）
SINGBOX_SOCKS5_PORT = 1080 # Singbox 本地 SOCKS5 代理端口
SINGBOX_HTTP_PORT = 1081 # Singbox 本地 HTTP 代理端口

async def run_singbox_test(node_url: str, session: aiohttp.ClientSession) -> bool:
    """
    概念性函数：通过 subprocess 调用 Singbox 进行节点测试。
    此函数需要您根据 Singbox 的实际用法进行完善。
    """
    print(f"尝试通过 Singbox 测试节点: {node_url}")
    
    # 1. 动态生成 Singbox 配置
    # 这里是一个非常简化的示例配置，您需要根据 node_url 的协议和参数来构建正确的配置。
    # 对于 hysteria2, vless, vmess, ss, trojan 等协议，配置结构会很不同。
    # 建议先手动创建一个能工作的 Singbox 配置文件，然后尝试用 Python 动态生成它。
    
    # 示例：假设 node_url 是一个可以直接用于 `outbounds` 的 URL
    config_content = {
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": SINGBOX_SOCKS5_PORT
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": SINGBOX_HTTP_PORT
            }
        ],
        "outbounds": [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": [node_url] # Singbox 可以在 urltest 中直接使用节点URL
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rule_set": [
                {
                    "tag": "proxy_rules",
                    "type": "field",
                    "outbound": "auto",
                    "domain": ["geosite:cn", "geosite:private"]
                }
            ],
            "default_outbound": "auto" # 默认流量走 auto (urltest)
        }
    }
    
    # 写入临时配置文件
    config_file_path = f"/tmp/singbox_config_{os.getpid()}.json"
    with open(config_file_path, "w", encoding="utf-8") as f:
        json.dump(config_content, f, indent=2)

    singbox_process = None
    try:
        # 2. 启动 Singbox 进程
        # 确保 sing-box 可执行文件在 PATH 中或提供完整路径
        command = ["sing-box", "run", "-c", config_file_path]
        singbox_process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"Singbox 进程启动中 (PID: {singbox_process.pid})...")
        await asyncio.sleep(2) # 等待 Singbox 启动

        # 3. 通过 Singbox 代理访问目标网站
        proxies = {
            "http": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}",
            "https": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}"
        }
        
        async with session.get(TARGET_URL, proxy=f"http://127.0.0.1:{SINGBOX_HTTP_PORT}", timeout=TEST_TIMEOUT) as response:
            if response.status == 200:
                print(f"通过 Singbox 访问 {TARGET_URL} 成功。")
                return True
            else:
                print(f"通过 Singbox 访问 {TARGET_URL} 失败，HTTP 状态码: {response.status}")
                return False

    except asyncio.TimeoutError:
        print(f"通过 Singbox 访问 {TARGET_URL} 超时。")
        return False
    except aiohttp.ClientError as e:
        print(f"通过 Singbox 访问 {TARGET_URL} 发生客户端错误: {e}")
        return False
    except FileNotFoundError:
        print("错误：'sing-box' 命令未找到。请确保 Singbox 已正确安装并添加到 PATH。")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Singbox 进程错误: {e}")
        print(f"Singbox stdout: {e.stdout}")
        print(f"Singbox stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"执行 Singbox 测试时发生未知错误: {e}")
        return False
    finally:
        # 4. 停止 Singbox 进程并清理
        if singbox_process:
            print(f"终止 Singbox 进程 (PID: {singbox_process.pid})...")
            singbox_process.terminate()
            try:
                singbox_process.wait(timeout=5) # 等待进程结束
            except subprocess.TimeoutExpired:
                print(f"强制杀死 Singbox 进程 (PID: {singbox_process.pid})...")
                singbox_process.kill()
        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            # print(f"已删除临时配置文件: {config_file_path}")

async def test_node_connectivity(session, node_url):
    """
    测试单个节点的连通性。
    """
    print(f"--> 开始测试节点: {node_url}")
    is_successful = await run_singbox_test(node_url, session)
    
    if is_successful:
        print(f"<-- 节点连通成功: {node_url}")
        return node_url
    else:
        print(f"<-- 节点连通失败: {node_url}")
        return None

async def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    nodes = []
    try:
        with open(SUB_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # 过滤掉注释行和空行，只保留节点链接
                if line and not line.startswith('#') and re.match(r"^(hysteria2|vless|vmess|ss|trojan|ssr)://", line):
                    nodes.append(line)
    except FileNotFoundError:
        print(f"错误：文件 {SUB_FILE} 未找到。请确保文件存在。")
        return

    if not nodes:
        print("未从 sub.txt 中读取到任何有效节点。")
        return

    print(f"共读取到 {len(nodes)} 个节点，开始并行测试...")

    successful_nodes = []
    
    # 异步并发执行，控制并发数。请根据 GitHub Actions 的资源和目标网站的QPS限制调整。
    # 对于 10W+ 节点，一次性全部并发可能导致资源耗尽或被封禁。
    # 建议采取分批处理或分布式测试策略。
    concurrency_limit = 50 # 建议从一个较小的值开始测试，例如 50 或 100

    connector = aiohttp.TCPConnector(limit=concurrency_limit) # 限制TCP连接数
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [test_node_connectivity(session, node) for node in nodes]
        # 使用 asyncio.as_completed 以便在任务完成时处理结果，而不是等待所有任务完成
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            if result:
                successful_nodes.append(result)
            
            # 每处理一定数量的节点打印进度
            if (i + 1) % 100 == 0 or (i + 1) == len(nodes):
                print(f"已处理 {i + 1} / {len(nodes)} 个节点，当前成功节点数: {len(successful_nodes)}")

    print(f"\n测试完成。成功节点数量: {len(successful_nodes)}")

    with open(ALL_FILE, 'w', encoding='utf-8') as f:
        # 确保目录存在
        os.makedirs(DATA_DIR, exist_ok=True)
        # 获取当前时间（在 GitHub Actions 上可能不是本地时区）
        current_time = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
        f.write(f"# Successful Nodes ({current_time})\n")
        f.write("-------------------------------------\n")
        for node in successful_nodes:
            f.write(node + "\n")

    print(f"成功节点已保存到 {ALL_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
