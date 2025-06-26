import asyncio
import json
import logging
import random
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import base64
import urllib.parse
import aiohttp
import binascii
import os
import yaml # 需要安装 PyYAML: pip install PyYAML

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量
NODE_FILE_PATH = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml"
OUTPUT_FILE_PATH = "data/all.txt"
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash") # Clash 可执行文件路径
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://1.1.1.1",
]
BATCH_SIZE = 1000  # 每批测试的节点数
MAX_CONCURRENT = 5  # 最大并发 Clash 实例
TIMEOUT = 10  # 每个节点测试的超时时间（秒）

# Clash 配置模板
# 注意：Clash 的配置是 YAML 格式
CLASH_CONFIG_TEMPLATE = {
    "port": 7890,          # HTTP 代理端口
    "socks-port": 7891,    # SOCKS5 代理端口 (我们将使用这个端口进行测试)
    "allow-lan": False,
    "mode": "rule",        # rule 模式，便于我们控制流量
    "log-level": "warning",
    "external-controller": "127.0.0.1:9090", # 控制器端口，方便调试，测试时可以不用
    "dns": {
        "enable": True,
        "listen": "0.0.0.0:53",
        "enhanced-mode": True,
        "fallback": [
            "tls://8.8.8.8:853",
            "tls://1.1.1.1:853"
        ],
        "default-nameserver": [
            "8.8.8.8",
            "1.1.1.1"
        ]
    },
    "proxies": [],
    "proxy-groups": [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": ["Direct"] # 初始为空，测试时会添加代理
        },
        {
            "name": "Direct",
            "type": "direct"
        }
    ],
    "rules": [
        "MATCH,Proxy" # 所有流量通过 Proxy 组
    ]
}

async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """
    解析 Shadowsocks 链接，返回 Clash 代理配置。
    支持标准 Shadowsocks 和 Shadowsocks 2022。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ss":
            return None

        # 分割凭据和服务器信息
        if "@" not in parsed.netloc:
            logger.warning(f"SS 链接格式无效（缺少@）: {url}")
            return None

        credentials_b64, server_info = parsed.netloc.split("@", 1)
        server, port_str = server_info.split(":", 1)
        port = int(port_str.split("?")[0]) # 处理端口后可能带参数的情况

        method = ""
        password = ""
        
        # 解码凭据
        try:
            # 尝试标准 base64 解码
            decoded_credentials = base64.b64decode(credentials_b64).decode("utf-8")
            if ":" in decoded_credentials:
                # 标准 Shadowsocks 格式：method:password
                method, password = decoded_credentials.split(":", 1)
            else:
                # 可能是 Shadowsocks 2022 的 base64 编码密钥，但没有明确的方法
                logger.warning(f"SS 链接凭据格式异常 (无冒号), 尝试作为 SS 2022 处理: {url}")
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8") # 密钥本身就是密码
        except (binascii.Error, UnicodeDecodeError) as e:
            # 可能是 Shadowsocks 2022 密钥，其原始字节串可能不是有效的UTF-8
            try:
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8") # 密钥本身就是密码
            except binascii.Error as inner_e:
                logger.warning(f"解析 SS 链接凭据失败: {url}, 错误: {inner_e}")
                return None

        # 解析查询参数
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Clash 中 Shadowsocks 的 method 对应 cipher
        # Shadowsocks 2022 的方法名称在 Clash 中是直接支持的
        proxy_config = {
            "name": f"ss-{server}-{port}", # 代理名称，Clash 需要
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method, # Shadowsocks 的加密方法
            "password": password,
        }

        # 检查是否有插件（obfs/v2ray-plugin）
        plugin = query_params.get("plugin", [None])[0]
        plugin_opts = query_params.get("plugin_opts", [None])[0]

        if plugin:
            if plugin == "obfs-local" or plugin == "simple-obfs":
                # Clash 的 obfs 配置是 { "obfs": "http", "obfs-host": "..." } 或 { "obfs": "tls", "obfs-host": "..." }
                # 需要解析 plugin_opts
                if "obfs=http" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "http"}
                    if "obfs-host" in plugin_opts:
                        host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                        if host:
                            proxy_config["plugin-opts"]["host"] = host.group(1)
                elif "obfs=tls" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "tls"}
                    if "obfs-host" in plugin_opts:
                        host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                        if host:
                            proxy_config["plugin-opts"]["host"] = host.group(1)
                else:
                    logger.warning(f"SS 链接: 未知或不支持的 obfs 插件模式: {plugin_opts}, 跳过插件配置: {url}")
            elif plugin == "v2ray-plugin":
                # Clash 的 v2ray-plugin 配置比较复杂，涉及 ws, grpc, tls 等
                # 通常是 "plugin": "v2ray-plugin", "plugin-opts": { "mode": "websocket", "tls": true, ... }
                logger.warning(f"SS 链接: v2ray-plugin 插件支持不完整，请手动检查: {url}")
                # 简单示例，可能需要更复杂的解析逻辑
                proxy_config["plugin"] = "v2ray-plugin"
                proxy_config["plugin-opts"] = {"mode": "websocket"} # 假设是 websocket
                if "tls" in plugin_opts:
                    proxy_config["plugin-opts"]["tls"] = True
                if "host" in plugin_opts:
                    host = re.search(r"host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
            else:
                logger.warning(f"SS 链接: 未知或不支持的插件类型: {plugin}, 跳过插件配置: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 SS 链接失败: {url}, 错误: {e}")
        return None

async def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    """
    解析 Hysteria2 链接，返回 Clash 代理配置。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "hysteria2":
            return None

        # 提取 UUID 和服务器信息
        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"Hysteria2 链接格式无效（缺少@）: {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        # 解析查询参数
        query_params = urllib.parse.parse_qs(parsed.query)

        password = query_params.get("password", [uuid_str])[0] # Hysteria2 密码通常是 UUID
        if "password" in query_params:
            password = query_params["password"][0]

        insecure = query_params.get("insecure", ["0"])[0].lower() == "1"
        sni = query_params.get("sni", [server])[0]
        alpn_str = query_params.get("alpn", ["h3"])[0]
        alpn = [alpn_str] if isinstance(alpn_str, str) else alpn_str
        
        obfs = query_params.get("obfs", [None])[0]
        obfs_password = query_params.get("obfs-password", [None])[0] # Clash 使用 obfs-password

        proxy_config = {
            "name": f"hysteria2-{server}-{port}", # 代理名称，Clash 需要
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "tls": True,
            "skip-cert-verify": insecure,
            "sni": sni,
            "alpn": alpn,
        }
        
        if obfs == "salamander" and obfs_password:
            proxy_config["obfs"] = "salamander"
            proxy_config["obfs-password"] = obfs_password
        elif obfs and obfs != "none":
            logger.warning(f"Hysteria2 链接中不支持的混淆类型: {obfs}, 跳过混淆配置: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 Hysteria2 链接失败: {url}, 错误: {e}")
        return None

async def generate_clash_config(proxy_entry: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    """生成 Clash 配置文件。"""
    config = CLASH_CONFIG_TEMPLATE.copy()
    config["socks-port"] = socks_port
    config["proxies"] = [proxy_entry] # 将单个代理添加到 proxies 列表中
    
    # 动态更新 proxy-groups 中的代理名称
    # 确保 Proxy 组使用当前正在测试的代理
    config["proxy-groups"][0]["proxies"] = [proxy_entry["name"], "Direct"] 

    return config

async def test_node(clash_config: Dict[str, Any], node_url: str, index: int, total: int) -> bool:
    """测试单个节点。"""
    temp_dir = Path(tempfile.gettempdir())
    
    # 每次测试分配一个唯一的 SOCKS5 端口
    # Clash 默认会同时开放 HTTP 和 SOCKS5 端口，这里我们指定 SOCKS5 端口
    socks_port = random.randint(20000, 25000)
    clash_config["socks-port"] = socks_port
    # HTTP 端口可以随意设置，只要不冲突
    clash_config["port"] = random.randint(10000, 15000) 
    
    config_path = temp_dir / f"clash_config_{os.getpid()}_{socks_port}.yaml"

    process = None # Initialize process to None
    try:
        # 写入配置文件
        with open(config_path, "w") as f:
            yaml.dump(clash_config, f, indent=2, sort_keys=False) # sort_keys=False 保持字典插入顺序

        # 启动 Clash
        # 使用 -f 指定配置文件，-d 指定工作目录（如果需要）
        process = await asyncio.create_subprocess_exec(
            CLASH_PATH,
            "-f",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # 等待 Clash 启动并检查其是否立即退出
        await asyncio.sleep(2) # 给 Clash 更多时间启动
        
        # 检查进程是否仍然存活
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Clash 启动失败 (节点: {node_url})")
            logger.error(f"配置文件内容:\n{yaml.dump(clash_config, indent=2, sort_keys=False)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        # 检查 SOCKS5 端口是否可连接
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', socks_port)
            writer.close()
            await reader.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Clash SOCKS5 端口 {socks_port} 未开放 (节点: {node_url})")
            process.terminate()
            await process.wait() # 等待进程终止
            return False
        except Exception as e:
            logger.warning(f"连接 SOCKS5 端口 {socks_port} 失败 (节点: {node_url}): {e}")
            process.terminate()
            await process.wait() # 等待进程终止
            return False

        # 测试 URL
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"socks5://127.0.0.1:{socks_port}"
            for url in TEST_URLS:
                try:
                    async with session.get(url, proxy=proxy) as response:
                        if response.status != 200:
                            logger.info(f"节点 {node_url} 测试 {url} 失败 (状态码: {response.status})")
                            process.terminate()
                            await process.wait()
                            return False
                except aiohttp.ClientConnectorError as e:
                    logger.info(f"节点 {node_url} 连接 {url} 失败: {e}")
                    process.terminate()
                    await process.wait()
                    return False
                except asyncio.TimeoutError:
                    logger.info(f"节点 {node_url} 测试 {url} 超时")
                    process.terminate()
                    await process.wait()
                    return False
                except Exception as e:
                    logger.info(f"节点 {node_url} 测试 {url} 失败: {e}")
                    process.terminate()
                    await process.wait()
                    return False

        logger.info(f"节点 {node_url} 通过所有测试")
        return True
    except Exception as e:
        logger.error(f"测试节点 {node_url} 出错: {e}")
        return False
    finally:
        # 确保进程被终止
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2) # 给一些时间让进程终止
            except asyncio.TimeoutError:
                logger.warning(f"未能正常终止 Clash 进程，强制杀死 (节点: {node_url})")
                process.kill()
        # 清理配置文件
        if config_path.exists():
            try:
                config_path.unlink()
            except OSError as e:
                logger.warning(f"无法删除配置文件 {config_path}: {e}")

async def main():
    """主函数：读取节点，测试并保存有效节点。"""
    # 确保 data 目录存在
    Path("data").mkdir(parents=True, exist_ok=True)

    # 读取节点
    nodes = []
    # 尝试从上传的文件中读取节点，如果文件不存在则从默认路径读取
    uploaded_nodes_file = Path("0_test-nodes.txt") # 这是用户提供的文件名
    
    # 初始化一个局部变量来保存实际使用的节点文件路径
    current_node_file_path = Path(NODE_FILE_PATH) 

    if uploaded_nodes_file.exists():
        current_node_file_path = uploaded_nodes_file
        logger.info(f"使用上传的文件作为节点源: {current_node_file_path}")
    else:
        logger.warning(f"上传文件 '{uploaded_nodes_file}' 未找到。使用默认节点文件路径: {current_node_file_path}")

    try:
        with open(current_node_file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("---"): # 忽略注释行和分隔线
                    nodes.append(line)
    except FileNotFoundError:
        logger.error(f"节点文件 '{current_node_file_path}' 不存在。请确保文件路径正确。")
        return
    except Exception as e:
        logger.error(f"读取节点文件失败: {e}")
        return

    logger.info(f"读取到 {len(nodes)} 个去重后的节点链接")
    if not nodes:
        logger.error("节点列表为空")
        return

    # 分批测试
    valid_nodes = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    # 确保 Clash 可执行文件存在且可执行
    if not Path(CLASH_PATH).is_file() or not os.access(CLASH_PATH, os.X_OK):
        logger.error(f"Clash 可执行文件 '{CLASH_PATH}' 不存在或不可执行。请检查 CLASH_CORE_PATH。")
        logger.error("请确保 GitHub Actions 工作流正确下载了 Clash 可执行文件并设置了执行权限。")
        return

    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        tasks = []
        for j, node_url in enumerate(batch):
            async def test_with_semaphore(idx: int, url: str):
                async with semaphore:
                    proxy_entry = None
                    if url.startswith("ss://"):
                        proxy_entry = await parse_shadowsocks(url)
                    elif url.startswith("hysteria2://"):
                        proxy_entry = await parse_hysteria2(url)
                    # 可以在这里添加其他协议的解析器，例如 VMess, Trojan, VLESS 等
                    # elif url.startswith("vmess://"):
                    #     proxy_entry = await parse_vmess(url)
                    # elif url.startswith("trojan://"):
                    #     proxy_entry = await parse_trojan(url)
                    else:
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 不支持的协议类型，已跳过")
                        return None

                    if not proxy_entry:
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 解析失败，已跳过")
                        return None
                    
                    # 生成 Clash 配置，这里不需要传递 port，它会在 test_node 内部生成
                    clash_config = await generate_clash_config(proxy_entry, 0) # 0 作为占位符，test_node 会分配实际端口
                    
                    if await test_node(clash_config, url, i + idx + 1, len(nodes)):
                        return url
                    logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 无效或延迟过高，已跳过")
                    return None

            tasks.append(test_with_semaphore(j, node_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        # 过滤掉异常和None
        valid_batch_nodes = [r for r in results if isinstance(r, str) and r is not None]
        valid_nodes.extend(valid_batch_nodes)

        # 保存中间结果 (可选，但对于大型列表有用)
        with open(f"data/temp_valid_{i}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_batch_nodes) + "\n")
        logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，当前有效节点数: {len(valid_nodes)}")

    # 保存最终结果
    if valid_nodes:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(valid_nodes) + "\n")
        logger.info(f"测试完成，保存 {len(valid_nodes)} 个有效节点到 {OUTPUT_FILE_PATH}")
    else:
        logger.warning("没有找到有效节点")

if __name__ == "__main__":
    asyncio.run(main())
