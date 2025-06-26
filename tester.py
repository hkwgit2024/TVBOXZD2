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
    """解析 Shadowsocks 链接，返回 Sing-box 配置。"""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ss":
            return None

        # 提取凭据（base64 编码部分）
        credentials = parsed.netloc.split("@")[0]
        server_info = parsed.netloc.split("@")[1]
        server, port = server_info.split(":")
        port = int(port)

        # 解码凭据
        try:
            decoded_credentials = base64.b64decode(credentials + "==").decode("utf-8")
            # 标准 Shadowsocks 格式：method:password
            method, password = decoded_credentials.split(":", 1)
            return {
                "type": "shadowsocks",
                "server": server,
                "server_port": port,
                "method": method,
                "password": password,
                "tag": "proxy",
            }
        except UnicodeDecodeError:
            # 非 UTF-8 凭据，可能是 Shadowsocks 2022 密钥
            decoded = base64.b64decode(credentials + "==")
            if len(decoded) not in (16, 32):
                logger.warning(f"SS 链接凭据长度无效 ({len(decoded)} 字节)，跳过: {url}")
                return None
            # 重新编码为标准 base64
            password = base64.b64encode(decoded).decode("utf-8")
            method = "2022-blake3-aes-256-gcm" if len(decoded) == 32 else "2022-blake3-aes-128-gcm"
            logger.info(f"SS 2022 密钥: {password} (方法: {method})")
            return {
                "type": "shadowsocks",
                "server": server,
                "server_port": port,
                "method": method,
                "password": password,
                "tag": "proxy",
            }
    except Exception as e:
        logger.warning(f"解析 SS 链接失败: {url}, 错误: {e}")
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

async def test_node(config: Dict[str, Any], node_name: str, index: int, total: int) -> bool:
    """测试单个节点。"""
    temp_dir = Path(tempfile.gettempdir())
    config_path = temp_dir / f"singbox_{index}.json"
    port = 20000 + index % 1000  # 动态分配端口

    try:
        # 写入配置文件
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        # 启动 Sing-box
        process = await asyncio.create_subprocess_exec(
            SINGBOX_PATH,
            "run",
            "-c",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # 等待 Sing-box 启动
        await asyncio.sleep(1)
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Singbox 启动失败 (节点: {node_name})")
            logger.error(f"配置文件内容: {json.dumps(config, indent=2)}")
            logger.error(f"Stdout: {stdout.decode()}")
            logger.error(f"Stderr: {stderr.decode()}")
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
                            logger.info(f"节点 {node_name} 测试 {url} 失败 (状态码: {response.status})")
                            process.terminate()
                            return False
                except Exception as e:
                    logger.info(f"节点 {node_name} 测试 {url} 失败: {e}")
                    process.terminate()
                    return False

        logger.info(f"节点 {node_name} 通过所有测试")
        process.terminate()
        return True
    except Exception as e:
        logger.error(f"测试节点 {node_name} 出错: {e}")
        return False
    finally:
        if "process" in locals():
            process.terminate()
            await asyncio.sleep(0.1)
            if process.returncode is None:
                process.kill()
        if config_path.exists():
            config_path.unlink()

async def main():
    """主函数：读取节点，测试并保存有效节点。"""
    # 读取节点
    nodes = []
    with open(NODE_FILE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                nodes.append(line)

    logger.info(f"读取到 {len(nodes)} 个去重后的节点链接")
    if not nodes:
        logger.error("节点列表为空")
        return

    # 分批测试
    valid_nodes = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        tasks = []
        for j, node_url in enumerate(batch):
            async def test_with_semaphore(idx: int, url: str):
                async with semaphore:
                    config = await parse_shadowsocks(url)
                    if not config:
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 解析失败，已跳过")
                        return None
                    singbox_config = await generate_singbox_config(config, 20000 + idx % 1000)
                    if await test_node(singbox_config, url, i + idx + 1, len(nodes)):
                        return url
                    logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {url} 无效或延迟过高，已跳过")
                    return None

            tasks.append(test_with_semaphore(j, node_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_nodes.extend([r for r in results if r and not isinstance(r, Exception)])

        # 保存中间结果
        with open(f"data/temp_valid_{i}.txt", "w") as f:
            f.write("\n".join(valid_nodes) + "\n")
        logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，当前有效节点数: {len(valid_nodes)}")

    # 保存最终结果
    if valid_nodes:
        with open(OUTPUT_FILE_PATH, "w") as f:
            f.write("\n".join(valid_nodes) + "\n")
        logger.info(f"测试完成，保存 {len(valid_nodes)} 个有效节点到 {OUTPUT_FILE_PATH}")
    else:
        logger.warning("没有找到有效节点")

if __name__ == "__main__":
    asyncio.run(main())
