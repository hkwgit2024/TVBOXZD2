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
import re
import os
import subprocess

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量
NODE_FILE_PATH = "data/sub_2.txt"
OUTPUT_FILE_PATH = "data/all.txt"
SINGBOX_PATH = os.getenv("SINGBOX_CORE_PATH", "./sing-box")
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://1.1.1.1",
]
BATCH_SIZE = 1000  # 每批测试的节点数
MAX_CONCURRENT = 5  # 最大并发 Sing-box 实例
TIMEOUT = 10  # 每个节点测试的超时时间（秒）

async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """
    解析 Shadowsocks 链接，返回 Sing-box 配置。
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

        # 解码凭据
        try:
            # 尝试标准 base64 解码
            decoded_credentials = base64.b64decode(credentials_b64).decode("utf-8")
            if ":" in decoded_credentials:
                # 标准 Shadowsocks 格式：method:password
                method, password = decoded_credentials.split(":", 1)
            else:
                # 可能是 Shadowsocks 2022 的 base64 编码密钥，但没有明确的方法
                # 或者是一个不完整/错误的链接
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
        
        # 提取插件信息 (如果存在)
        plugin = query_params.get("plugin", [None])[0]
        plugin_opts = query_params.get("plugin_opts", [None])[0]

        outbound = {
            "type": "shadowsocks",
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
            "tag": "proxy",
        }

        # 添加插件配置（如果适用）
        if plugin and plugin_opts:
            # 这里需要根据具体的 plugin 类型来构建 Sing-box 的 transport 配置
            # 对于 ss:// 链接，通常插件是 simple-obfs 或 v2ray-plugin
            # 由于 Sing-box 对这些有特定的 transport 配置方式，这里只是一个示例
            # 实际情况需要更复杂的逻辑来解析 plugin_opts
            logger.warning(f"检测到 SS 插件: {plugin}，但目前未完全支持其配置生成: {url}")
            # 假设 simple-obfs 插件
            if plugin == "obfs-local" or plugin == "simple-obfs":
                if "tls" in plugin_opts:
                    outbound["network"] = "tcp" # 默认是 tcp，但显式声明
                    outbound["tls"] = { "enabled": True, "server_name": server}
                    # obfs-host or obfs-header in plugin_opts might be complex
                elif "http" in plugin_opts:
                    outbound["network"] = "tcp"
                    # Add http obfuscation config here, which is not directly supported by simple "type": "shadowsocks" in singbox
                    # This would typically require a 'chain' or 'warp' outbound structure in singbox,
                    # or defining a specific transport based on the plugin.
                    logger.warning("Simple-obfs http mode is complex and not fully implemented.")

        return outbound
    except Exception as e:
        logger.warning(f"解析 SS 链接失败: {url}, 错误: {e}")
        return None


async def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    """
    解析 Hysteria2 链接，返回 Sing-box 配置。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "hysteria2":
            return None

        # 提取 UUID 和服务器信息
        # netloc 格式通常是 uuid@server:port
        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"Hysteria2 链接格式无效（缺少@）: {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        # 解析查询参数
        query_params = urllib.parse.parse_qs(parsed.query)

        # 提取 Hysteria2 特有参数
        password = query_params.get("password", [uuid_str])[0] # Hysteria2 密码通常是 UUID
        # 如果链接中有显式 password 参数，则使用它
        if "password" in query_params:
            password = query_params["password"][0]

        insecure = query_params.get("insecure", ["0"])[0].lower() == "1"
        sni = query_params.get("sni", [server])[0]
        alpn = query_params.get("alpn", ["h3"])[0] # Hysteria2 默认 alpn 是 h3
        obfs = query_params.get("obfs", [None])[0]
        obfs_param = query_params.get("obfs-param", [None])[0]

        # 构建 Hysteria2 的 Sing-box outbound 配置
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {
                "enabled": True,
                "insecure": insecure,
                "server_name": sni,
                "alpn": [alpn] if isinstance(alpn, str) else alpn, # Ensure alpn is a list
            }
        }

        if obfs == "salamander" and obfs_param:
            outbound["obfs"] = {
                "type": "salamander",
                "password": obfs_param # Salamander obfs param is its password
            }
        elif obfs and obfs != "none":
            logger.warning(f"Hysteria2 链接中不支持的混淆类型: {obfs}, 跳过混淆配置: {url}")

        return outbound
    except Exception as e:
        logger.warning(f"解析 Hysteria2 链接失败: {url}, 错误: {e}")
        return None

async def generate_singbox_config(outbound: Dict[str, Any], port: int) -> Dict[str, Any]:
    """生成 Sing-box 配置文件。"""
    return {
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": port,
                "sniff": True,
                "sniff_override_destination": True,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"address": "8.8.8.8", "strategy": "prefer_ipv4"},
                {"address": "1.1.1.1", "strategy": "prefer_ipv4"},
            ]
        },
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"network": "tcp,udp", "outbound": "proxy"},
            ],
            "final": "proxy",
        },
    }

async def test_node(config: Dict[str, Any], node_url: str, index: int, total: int) -> bool:
    """测试单个节点。"""
    temp_dir = Path(tempfile.gettempdir())
    # 使用随机端口号以避免冲突，同时确保在合理范围内
    port = random.randint(20000, 25000)
    config_path = temp_dir / f"singbox_config_{os.getpid()}_{port}.json"

    process = None # Initialize process to None
    try:
        # 写入配置文件
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        # 启动 Sing-box
        # 将 stderr 和 stdout 重定向到 PIPE 以捕获输出
        process = await asyncio.create_subprocess_exec(
            SINGBOX_PATH,
            "run",
            "-c",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # 等待 Sing-box 启动并检查其是否立即退出
        # 给 Sing-box 一点时间启动，并检查端口是否开放
        await asyncio.sleep(1.5) # 稍微增加等待时间
        
        # 检查进程是否仍然存活
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Singbox 启动失败 (节点: {node_url})")
            logger.error(f"配置文件内容: {json.dumps(config, indent=2)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        # 检查 SOCKS5 端口是否可连接
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.close()
            await reader.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Singbox SOCKS5 端口 {port} 未开放 (节点: {node_url})")
            process.terminate()
            await process.wait() # 等待进程终止
            return False
        except Exception as e:
            logger.warning(f"连接 SOCKS5 端口 {port} 失败 (节点: {node_url}): {e}")
            process.terminate()
            await process.wait() # 等待进程终止
            return False

        # 测试 URL
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"socks5://127.0.0.1:{port}"
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
                logger.warning(f"未能正常终止 Singbox 进程，强制杀死 (节点: {node_url})")
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
    uploaded_nodes_file = Path("0_test-nodes.txt") # This is the file name the user provided
    if uploaded_nodes_file.exists():
        NODE_FILE_PATH = uploaded_nodes_file
        logger.info(f"Using uploaded file as node source: {NODE_FILE_PATH}")
    else:
        # Fallback to the default path if the uploaded file is not found
        logger.warning(f"Uploaded file '{uploaded_nodes_file}' not found. Using default node file path: {NODE_FILE_PATH}")

    try:
        with open(NODE_FILE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("---"): # 忽略注释行和分隔线
                    nodes.append(line)
    except FileNotFoundError:
        logger.error(f"节点文件 '{NODE_FILE_PATH}' 不存在。请确保文件路径正确。")
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
    
    # 确保 temp 目录存在且 Sing-box 可执行
    if not Path(SINGBOX_PATH).is_file() or not os.access(SINGBOX_PATH, os.X_OK):
        logger.error(f"Sing-box 可执行文件 '{SINGBOX_PATH}' 不存在或不可执行。请检查 SINGBOX_CORE_PATH。")
        return

    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        tasks = []
        for j, node_url in enumerate(batch):
            async def test_with_semaphore(idx: int, url: str):
                async with semaphore:
                    config = None
                    if url.startswith("ss://"):
                        config = await parse_shadowsocks(url)
                    elif url.startswith("hysteria2://"):
                        config = await parse_hysteria2(url)
                    # 可以在这里添加其他协议的解析器
                    # elif url.startswith("vmess://"):
                    #     config = await parse_vmess(url)
                    # elif url.startswith("trojan://"):
                    #     config = await parse_trojan(url)
                    else:
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 不支持的协议类型，已跳过")
                        return None

                    if not config:
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 解析失败，已跳过")
                        return None
                    
                    # 每次测试分配一个唯一的端口
                    current_port = 20000 + (os.getpid() * 1000 + idx) % 10000 # 确保端口唯一性
                    singbox_config = await generate_singbox_config(config, current_port)
                    
                    if await test_node(singbox_config, url, i + idx + 1, len(nodes)):
                        return url
                    logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 无效或延迟过高，已跳过")
                    return None

            tasks.append(test_with_semaphore(j, node_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        # 过滤掉异常和None
        valid_batch_nodes = [r for r in results if isinstance(r, str) and r is not None]
        valid_nodes.extend(valid_batch_nodes)

        # 保存中间结果 (可选，但对于大型列表有用)
        # 注意: 如果分批保存到同一个文件，需要使用追加模式
        # 或者如原代码所示，保存到临时文件并最后合并
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
