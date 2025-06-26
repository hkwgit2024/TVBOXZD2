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
import yaml  # 需要安装 PyYAML: pip install PyYAML
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量
OUTPUT_FILE_PATH = "data/all.txt"
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash")  # Clash 可执行文件路径
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://1.1.1.1",
]
BATCH_SIZE = 1000  # 每批测试的节点数
MAX_CONCURRENT = 5  # 最大并发 Clash 实例
TIMEOUT = 10  # 每个节点测试的超时时间（秒）

# Clash 基础配置的下载 URL
CLASH_BASE_CONFIG_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml"

# 全局变量用于存储下载和解析后的 Clash 基础配置模板
GLOBAL_CLASH_CONFIG_TEMPLATE: Optional[Dict[str, Any]] = None


async def fetch_clash_base_config(url: str) -> Optional[Dict[str, Any]]:
    """
    从指定 URL 下载并解析 Clash 基础配置文件。
    """
    async with aiohttp.ClientSession() as session:
        try:
            logger.info(f"正在从 {url} 下载 Clash 基础配置...")
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()  # 检查 HTTP 响应状态码
                content = await response.text()
                logger.info("Clash 基础配置下载成功。")
                return yaml.safe_load(content)
        except aiohttp.ClientError as e:
            logger.error(f"下载 Clash 基础配置失败: {e}")
            return None
        except yaml.YAMLError as e:
            logger.error(f"解析 Clash 基础配置 YAML 失败: {e}")
            return None
        except asyncio.TimeoutError:
            logger.error(f"下载 Clash 基础配置超时: {url}")
            return None
        except Exception as e:
            logger.error(f"下载或解析 Clash 基础配置时发生未知错误: {e}")
            return None


async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """
    解析 Shadowsocks 链接，返回 Clash 代理配置。
    支持标准 Shadowsocks 和 Shadowsocks 2022。
    注意：在当前脚本中，如果直接从 Clash YAML 文件获取代理，此函数可能不会被调用。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ss":
            return None

        if "@" not in parsed.netloc:
            logger.warning(f"SS 链接格式无效（缺少@）: {url}")
            return None

        credentials_b64, server_info = parsed.netloc.split("@", 1)
        server, port_str = server_info.split(":", 1)
        port = int(port_str.split("?")[0])

        method = ""
        password = ""

        try:
            decoded_credentials = base64.b64decode(credentials_b64).decode("utf-8")
            if ":" in decoded_credentials:
                method, password = decoded_credentials.split(":", 1)
            else:
                logger.warning(f"SS 链接凭据格式异常 (无冒号), 尝试作为 SS 2022 处理: {url}")
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            try:
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
            except binascii.Error as inner_e:
                logger.warning(f"解析 SS 链接凭据失败: {url}, 错误: {inner_e}")
                return None

        query_params = urllib.parse.parse_qs(parsed.query)

        proxy_config = {
            "name": f"ss-{server}-{port}",
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
        }

        plugin = query_params.get("plugin", [None])[0]
        plugin_opts = query_params.get("plugin_opts", [None])[0]

        if plugin:
            if plugin == "obfs-local" or plugin == "simple-obfs":
                if "obfs=http" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "http"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                elif "obfs=tls" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "tls"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                else:
                    logger.warning(f"SS 链接: 未知或不支持的 obfs 插件模式: {plugin_opts}, 跳过插件配置: {url}")
            elif plugin == "v2ray-plugin":
                logger.warning(f"SS 链接: v2ray-plugin 插件支持不完整，请手动检查: {url}")
                proxy_config["plugin"] = "v2ray-plugin"
                proxy_config["plugin-opts"] = {"mode": "websocket"}
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
    注意：在当前脚本中，如果直接从 Clash YAML 文件获取代理，此函数可能不会被调用。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "hysteria2":
            return None

        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"Hysteria2 链接格式无效（缺少@）: {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        query_params = urllib.parse.parse_qs(parsed.query)

        password = query_params.get("password", [uuid_str])[0]
        if "password" in query_params:
            password = query_params["password"][0]

        insecure = query_params.get("insecure", ["0"])[0].lower() == "1"
        sni = query_params.get("sni", [server])[0]
        alpn_str = query_params.get("alpn", ["h3"])[0]
        alpn = [alpn_str] if isinstance(alpn_str, str) else alpn_str

        obfs = query_params.get("obfs", [None])[0]
        obfs_password = query_params.get("obfs-password", [None])[0]

        proxy_config = {
            "name": f"hysteria2-{server}-{port}",
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
    # 使用全局的下载模板确保包含必要的配置（如 rules、dns 等）
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        raise ValueError("Clash 基础配置模板未加载。请先调用 fetch_clash_base_config。")

    # 对 GLOBAL_CLASH_CONFIG_TEMPLATE 进行深拷贝
    config = json.loads(json.dumps(GLOBAL_CLASH_CONFIG_TEMPLATE))

    # 设置端口
    config["port"] = random.randint(10000, 15000)
    config["socks-port"] = socks_port

    # 确保 proxies 键存在且是列表，并只添加当前测试的代理
    config.setdefault("proxies", []).clear()
    config["proxies"].append(proxy_entry)

    # 构建 proxy-groups，仅包含一个主 Proxy 组，引用当前代理、DIRECT 和 REJECT
    config["proxy-groups"] = [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": [proxy_entry["name"], "DIRECT", "REJECT"]
        }
    ]

    # 确保 rules 存在且包含 MATCH,Proxy
    if "rules" not in config or not isinstance(config["rules"], list):
        config["rules"] = []
    if "MATCH,Proxy" not in config["rules"]:
        config["rules"].append("MATCH,Proxy")

    return config


async def test_node(clash_config: Dict[str, Any], node_identifier: str, index: int, total: int) -> bool:
    """测试单个节点。
    node_identifier 用于日志输出，可以是代理的名称或原始 URL。
    """
    temp_dir = Path(tempfile.gettempdir())
    
    # 每次测试分配一个唯一的 SOCKS5 端口
    socks_port = random.randint(20000, 25000)
    clash_config["socks-port"] = socks_port
    clash_config["port"] = random.randint(10000, 15000)  # HTTP 端口，随意设置

    config_path = temp_dir / f"clash_config_{os.getpid()}_{socks_port}.yaml"

    process = None
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(clash_config, f, indent=2, sort_keys=False, allow_unicode=True)

        process = await asyncio.create_subprocess_exec(
            CLASH_PATH,
            "-f",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.sleep(2)
        
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Clash 启动失败 (节点: {node_identifier})")
            logger.error(f"配置文件内容:\n{yaml.dump(clash_config, indent=2, sort_keys=False, allow_unicode=True)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', socks_port)
            writer.close()
            await writer.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Clash SOCKS5 端口 {socks_port} 未开放 (节点: {node_identifier})")
            process.terminate()
            await process.wait()
            return False
        except Exception as e:
            logger.warning(f"连接 SOCKS5 端口 {socks_port} 失败 (节点: {node_identifier}): {e}")
            process.terminate()
            await process.wait()
            return False

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"socks5://127.0.0.1:{socks_port}"
            for url in TEST_URLS:
                try:
                    async with session.get(url, proxy=proxy) as response:
                        if response.status != 200:
                            logger.info(f"节点 {node_identifier} 测试 {url} 失败 (状态码: {response.status})")
                            process.terminate()
                            await process.wait()
                            return False
                except aiohttp.ClientConnectorError as e:
                    logger.info(f"节点 {node_identifier} 连接 {url} 失败: {e}")
                    process.terminate()
                    await process.wait()
                    return False
                except asyncio.TimeoutError:
                    logger.info(f"节点 {node_identifier} 测试 {url} 超时")
                    process.terminate()
                    await process.wait()
                    return False
                except Exception as e:
                    logger.info(f"节点 {node_identifier} 测试 {url} 失败: {e}")
                    process.terminate()
                    await process.wait()
                    return False

        logger.info(f"节点 {node_identifier} 通过所有测试")
        return True
    except Exception as e:
        logger.error(f"测试节点 {node_identifier} 出错: {e}")
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                logger.warning(f"未能正常终止 Clash 进程，强制杀死 (节点: {node_identifier})")
                process.kill()
        if config_path.exists():
            try:
                config_path.unlink()
            except OSError as e:
                logger.warning(f"无法删除配置文件 {config_path}: {e}")


async def main():
    """主函数：读取节点，测试并保存有效节点。"""
    # 确保 data 目录存在
    Path("data").mkdir(parents=True, exist_ok=True)

    # 从 GitHub URL 下载 Clash 基础配置
    global GLOBAL_CLASH_CONFIG_TEMPLATE
    GLOBAL_CLASH_CONFIG_TEMPLATE = await fetch_clash_base_config(CLASH_BASE_CONFIG_URL)
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        logger.error("无法获取 Clash 基础配置，程序退出。")
        return

    # 从下载的 Clash 配置中提取节点
    nodes: List[Dict[str, Any]] = GLOBAL_CLASH_CONFIG_TEMPLATE.get("proxies", [])
    
    # 确保每个代理都有一个 'name' 字段，Clash 要求
    for i, node_proxy_dict in enumerate(nodes):
        if "name" not in node_proxy_dict:
            node_proxy_dict["name"] = f"unnamed-proxy-{i}"
            logger.warning(f"检测到一个没有 'name' 字段的代理，已为其生成名称: {node_proxy_dict['name']}")

    logger.info(f"从 Clash 基础配置中读取到 {len(nodes)} 个代理节点")
    if not nodes:
        logger.error("节点列表为空，可能是 Clash 基础配置中没有 'proxies' 列表或列表为空。")
        return

    # 分批测试
    valid_proxy_dicts: List[Dict[str, Any]] = []  # 存储有效的代理字典
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    
    # 确保 Clash 可执行文件存在且可执行
    if not Path(CLASH_PATH).is_file() or not os.access(CLASH_PATH, os.X_OK):
        logger.error(f"Clash 可执行文件 '{CLASH_PATH}' 不存在或不可执行。请检查 CLASH_CORE_PATH。")
        logger.error("请确保 GitHub Actions 工作流正确下载了 Clash 可执行文件并设置了执行权限。")
        return

    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        tasks = []
        for j, proxy_entry in enumerate(batch):
            async def test_with_semaphore(idx: int, entry: Dict[str, Any]):
                async with semaphore:
                    node_identifier = entry.get("name", "未知代理")
                    clash_config = await generate_clash_config(entry, 0)
                    
                    if await test_node(clash_config, node_identifier, i + idx + 1, len(nodes)):
                        return entry  # 返回完整的代理字典
                    logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ 节点 {node_identifier} 无效或延迟过高，已跳过")
                    return None

            tasks.append(test_with_semaphore(j, proxy_entry))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_batch_proxy_dicts = [r for r in results if isinstance(r, dict) and r is not None]
        valid_proxy_dicts.extend(valid_batch_proxy_dicts)

        # 保存中间结果 (用于调试或查看批次进度)
        if valid_batch_proxy_dicts:
            with open(f"data/temp_valid_batch_{i//BATCH_SIZE + 1}.yaml", "w", encoding="utf-8") as f:
                yaml.dump({"proxies": valid_batch_proxy_dicts}, f, indent=2, sort_keys=False, allow_unicode=True)
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，当前有效节点数: {len(valid_proxy_dicts)}")
        else:
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，此批次无有效节点。")

    # 保存最终结果
    if valid_proxy_dicts:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.dump({"proxies": valid_proxy_dicts}, f, indent=2, sort_keys=False, allow_unicode=True)
        logger.info(f"测试完成，保存 {len(valid_proxy_dicts)} 个有效节点到 {OUTPUT_FILE_PATH}")
    else:
        logger.warning("没有找到有效节点")


if __name__ == "__main__":
    asyncio.run(main())
