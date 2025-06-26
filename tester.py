import asyncio
import json
import logging
import random
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set # 导入 Set 类型
import base64
import urllib.parse
import aiohttp
import binascii
import os
import yaml
import re
import sys

# 确保 Python 版本为 3.7 或更高
if sys.version_info < (3, 7):
    raise RuntimeError("此脚本需要 Python 3.7 或更高版本")

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量
OUTPUT_FILE_PATH = "data/all.txt"
FAILED_NODES_FILE = "data/failed_nodes.txt" # 新增：用于存储无效节点的文件
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash")
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.cloudflare.com",
    "https://api.github.com",  # 添加 GitHub API 作为备选
]
BATCH_SIZE = 500  # 减小批次大小以降低资源压力
MAX_CONCURRENT = 10  # 减少并发数
TIMEOUT = 2  # 增加超时时间
CLASH_BASE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    #"https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml",
]

# 全局变量
GLOBAL_CLASH_CONFIG_TEMPLATE: Optional[Dict[str, Any]] = None

def load_failed_nodes(file_path: Path) -> Set[str]:
    """从文件中加载已知的无效节点名称"""
    if not file_path.exists():
        return set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logger.error(f"加载无效节点文件 {file_path} 失败: {e}")
        return set()

def save_failed_node(file_path: Path, node_name: str):
    """将无效节点名称保存到文件"""
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{node_name}\n")
    except Exception as e:
        logger.error(f"保存无效节点 {node_name} 到文件 {file_path} 失败: {e}")


async def fetch_clash_base_config(url: str) -> Optional[Dict[str, Any]]:
    """从指定 URL 下载并解析 Clash 配置文件"""
    async with aiohttp.ClientSession() as session:
        try:
            logger.info(f"正在从 {url} 下载 Clash 配置...")
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                content = await response.text()
                logger.info(f"成功从 {url} 下载配置")
                return yaml.safe_load(content)
        except aiohttp.ClientError as e:
            logger.error(f"下载 Clash 配置失败 ({url}): {e}")
            return None
        except yaml.YAMLError as e:
            logger.error(f"解析 YAML 失败 ({url}): {e}")
            return None
        except asyncio.TimeoutError:
            logger.error(f"下载 Clash 配置超时 ({url})")
            return None
        except Exception as e:
            logger.error(f"下载或解析 Clash 配置时发生未知错误 ({url}): {e}")
            return None

async def fetch_all_configs(urls: List[str]) -> List[Dict[str, Any]]:
    """从多个 URL 获取代理节点，合并并去重"""
    nodes: List[Dict[str, Any]] = []
    seen_nodes = set()

    for url in urls:
        config = await fetch_clash_base_config(url)
        if config is None:
            logger.warning(f"无法从 {url} 获取节点，跳过")
            continue

        proxies = config.get("proxies", [])
        if not proxies:
            logger.warning(f"从 {url} 获取的配置中没有 proxies 列表")
            continue

        for proxy in proxies:
            unique_key = (
                proxy.get("server", ""),
                proxy.get("port", 0),
                proxy.get("cipher", ""),
                proxy.get("password", ""),
                proxy.get("type", "")
            )
            if unique_key in seen_nodes:
                logger.debug(f"跳过重复节点: {proxy.get('name', '未知')}")
                continue
            seen_nodes.add(unique_key)
            nodes.append(proxy)

        logger.info(f"从 {url} 获取 {len(proxies)} 个节点，合并后总计 {len(nodes)} 个唯一节点")

    return nodes

async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """解析 Shadowsocks 链接，返回 Clash 代理配置"""
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
                logger.warning(f"SS 链接凭据格式异常（无冒号），尝试作为 SS 2022 处理: {url}")
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"SS 链接凭据长度无效 ({len(key_bytes)} 字节)，跳过: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
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
            except binascii.Error as e:
                logger.warning(f"解析 SS 链接凭据失败: {url}, 错误: {e}")
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
            if plugin in ("obfs-local", "simple-obfs"):
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
                    logger.warning(f"SS 链接: 未知或不支持的 obfs 插件模式: {plugin_opts}, 继续测试: {url}")
            elif plugin == "v2ray-plugin":
                logger.warning(f"SS 链接: v2ray-plugin 支持不完整，继续测试: {url}")
                proxy_config["plugin"] = "v2ray-plugin"
                proxy_config["plugin-opts"] = {"mode": "websocket"}
                if "tls" in plugin_opts:
                    proxy_config["plugin-opts"]["tls"] = True
                if "host" in plugin_opts:
                    host = re.search(r"host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
            else:
                logger.warning(f"SS 链接: 未知插件类型: {plugin}, 继续测试: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 SS 链接失败: {url}, 错误: {e}")
        return None

async def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    """解析 Hysteria2 链接，返回 Clash 代理配置"""
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
            logger.warning(f"Hysteria2 链接中不支持的混淆类型: {obfs}, 继续测试: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"解析 Hysteria2 链接失败: {url}, 错误: {e}")
        return None

def validate_proxy_entry(proxy_entry: Dict[str, Any]) -> bool:
    """验证代理节点格式是否符合 Clash 要求"""
    supported_protocols = ["ss", "vmess", "hysteria2", "vless", "trojan"]
    supported_ciphers = ["chacha20-ietf-poly1305", "aes-128-gcm", "2022-blake3-aes-128-gcm", "aes-256-gcm"]
    try:
        if not isinstance(proxy_entry, dict):
            raise ValueError("代理节点必须为字典格式")

        if "type" not in proxy_entry:
            raise ValueError("代理节点缺少 'type' 字段")

        if proxy_entry["type"] not in supported_protocols:
            logger.warning(f"不支持的代理协议类型: {proxy_entry['type']}. 支持的协议: {supported_protocols}, 继续测试")
            return True  # 放宽限制，允许测试

        if "name" not in proxy_entry:
            proxy_entry["name"] = f"{proxy_entry['type']}-{proxy_entry.get('server', 'unknown')}-{proxy_entry.get('port', '0')}"
            logger.warning(f"代理节点缺少 'name' 字段，已生成: {proxy_entry['name']}")

        if "server" not in proxy_entry:
            raise ValueError("代理节点缺少 'server' 字段")

        if "port" not in proxy_entry:
            raise ValueError("代理节点缺少 'port' 字段")

        if proxy_entry["server"] == "1.1.1.1" and proxy_entry["port"] == 1:
            logger.warning(f"跳过无效节点: {proxy_entry['name']}")
            return False

        if proxy_entry["type"] == "ss":
            if "cipher" not in proxy_entry or "password" not in proxy_entry:
                raise ValueError("Shadowsocks 节点缺少 'cipher' 或 'password' 字段")
            if proxy_entry["cipher"] not in supported_ciphers:
                logger.warning(f"不支持的 Shadowsocks 加密方式: {proxy_entry['cipher']}. 支持的加密方式: {supported_ciphers}, 继续测试")
                return True
        elif proxy_entry["type"] == "vmess":
            if "uuid" not in proxy_entry or "cipher" not in proxy_entry:
                raise ValueError("VMess 节点缺少 'uuid' 或 'cipher' 字段")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                logger.warning(f"VMess WebSocket 节点缺少 'ws-opts' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "hysteria2":
            if "password" not in proxy_entry and "auth" not in proxy_entry:
                raise ValueError("Hysteria2 节点缺少 'password' 或 'auth' 字段")
            if proxy_entry.get("obfs") and "obfs-password" not in proxy_entry:
                logger.warning(f"Hysteria2 节点启用了 obfs 但缺少 'obfs-password' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "vless":
            if "uuid" not in proxy_entry or "tls" not in proxy_entry:
                raise ValueError("VLESS 节点缺少 'uuid' 或 'tls' 字段")
            if proxy_entry.get("flow") == "xtls-rprx-vision" and "reality-opts" not in proxy_entry:
                logger.warning(f"VLESS 节点使用 xtls-rprx-vision 流控但缺少 'reality-opts' 字段，继续测试")
                return True
        elif proxy_entry["type"] == "trojan":
            if "password" not in proxy_entry:
                raise ValueError("Trojan 节点缺少 'password' 字段")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                logger.warning(f"Trojan WebSocket 节点缺少 'ws-opts' 字段，继续测试")
                return True

        return True
    except ValueError as e:
        logger.warning(f"节点 {proxy_entry.get('name', '未知')} 验证失败: {str(e)}. 完整配置: {proxy_entry}")
        return False

async def generate_clash_config(proxy_entry: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    """为单个代理节点生成 Clash 配置文件"""
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        raise ValueError("Clash 基础配置模板未加载。请先调用 fetch_clash_base_config")

    if not validate_proxy_entry(proxy_entry):
        raise ValueError(f"无效代理节点 {proxy_entry.get('name', '未知')}，跳过生成")

    config = json.loads(json.dumps(GLOBAL_CLASH_CONFIG_TEMPLATE))

    config["port"] = random.randint(10000, 15000)
    config["socks-port"] = socks_port
    config["allow-lan"] = False
    config["mode"] = "rule"
    config["log-level"] = "debug"  # 增加调试日志

    config.setdefault("proxies", []).clear()
    config["proxies"].append(proxy_entry)

    proxy_name = proxy_entry["name"]
    config["proxy-groups"] = [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": [proxy_name, "DIRECT", "REJECT"]
        }
    ]

    if "rules" not in config or not isinstance(config["rules"], list):
        config["rules"] = [
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-SUFFIX,youtube.com,Proxy",
            "DOMAIN-SUFFIX,cloudflare.com,Proxy",
            "DOMAIN-SUFFIX,github.com,Proxy",
            "MATCH,Proxy"
        ]
    elif "MATCH,Proxy" not in config["rules"]:
        config["rules"].append("MATCH,Proxy")

    return config

async def test_node(clash_config: Dict[str, Any], node_identifier: str, index: int, total: int) -> bool:
    """测试单个代理节点"""
    temp_dir = Path(tempfile.gettempdir())
    socks_port = random.randint(20000, 25000)
    clash_config["socks-port"] = socks_port
    clash_config["port"] = random.randint(10000, 15000)

    config_path = temp_dir / f"clash_config_{os.getpid()}_{socks_port}.yaml"
    process = None
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)

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
            logger.error(f"配置文件内容:\n{yaml.dump(clash_config, indent=2, sort_keys=False)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', socks_port)
            writer.close()
            await writer.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Clash SOCKS5 端口 {socks_port} 未开放 (节点: {node_identifier})")
            return False
        except Exception as e:
            logger.warning(f"连接 SOCKS5 端口 {socks_port} 失败 (节点: {node_identifier}): {e}")
            return False

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"socks5://127.0.0.1:{socks_port}"
            for url in TEST_URLS:
                # 只尝试一次，不进行重试
                try:
                    async with session.get(url, proxy=proxy) as response:
                        if response.status != 200:
                            logger.info(
                                f"节点 {node_identifier} 连接 {url} 失败 "
                                f"(状态码: {response.status}, 尝试 1/1)"
                            )
                            return False # 失败则立即返回 False
                        break # 成功则跳出内层循环
                except aiohttp.ClientConnectionError as e:
                    logger.info(
                        f"节点 {node_identifier} 连接 {url} 失败: {e} "
                        f"(尝试 1/1)"
                    )
                    return False
                except asyncio.TimeoutError:
                    logger.info(
                        f"节点 {node_identifier} 测试 {url} 超时 "
                        f"(尝试 1/1)"
                    )
                    return False
                except Exception as e:
                    logger.info(
                        f"节点 {node_identifier} 测试 {url} 失败: {e} "
                        f"(尝试 1/1)"
                    )
                    return False

        logger.info(f"[{index}/{total}] ✓ 节点 {node_identifier} 通过所有测试")
        return True
    except Exception as e:
        logger.error(f"测试节点 {node_identifier} 失败: {e}")
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                logger.warning(f"无法正常终止 Clash 进程 (节点: {node_identifier})，强制杀死")
                process.kill()
        if config_path.exists():
            try:
                config_path.unlink()
            except OSError as e:
                logger.warning(f"无法删除配置文件 {config_path}: {e}")

async def main():
    """主函数：从多个 URL 加载代理节点，测试并保存有效节点"""
    Path("data").mkdir(parents=True, exist_ok=True)

    global GLOBAL_CLASH_CONFIG_TEMPLATE
    for url in CLASH_BASE_CONFIG_URLS:
        GLOBAL_CLASH_CONFIG_TEMPLATE = await fetch_clash_base_config(url)
        if GLOBAL_CLASH_CONFIG_TEMPLATE is not None:
            logger.info(f"使用 {url} 作为 Clash 配置模板")
            break
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        logger.error("无法从任何 URL 获取 Clash 基础配置，程序退出")
        return

    # 加载已知的无效节点列表
    known_failed_nodes = load_failed_nodes(Path(FAILED_NODES_FILE))
    logger.info(f"已加载 {len(known_failed_nodes)} 个上次运行的无效节点。")

    nodes = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)

    for i, node_proxy_dict in enumerate(nodes):
        if "name" not in node_proxy_dict:
            node_proxy_dict["name"] = f"proxy-{i}"
            logger.warning(f"检测到无 'name' 字段的代理，已生成: {node_proxy_dict['name']}")

    logger.info(f"去重后总计 {len(nodes)} 个唯一代理节点")
    if not nodes:
        logger.error("节点列表为空，可能是所有配置中没有 proxies 列表或列表为空")
        return

    if not Path(CLASH_PATH).is_file() or not os.access(CLASH_PATH, os.X_OK):
        logger.error(f"Clash 可执行文件 '{CLASH_PATH}' 不存在或不可执行。请检查 CLASH_CORE_PATH")
        return

    valid_proxy_dicts: List[Dict[str, Any]] = []
    failure_reasons: Dict[str, int] = {"server_disconnected": 0, "invalid_format": 0, "timeout": 0, "other": 0}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    # 过滤掉已知的无效节点，并准备进行测试的节点列表
    nodes_to_test = []
    skipped_count = 0
    for node in nodes:
        node_name = node.get("name", "未知代理")
        if node_name in known_failed_nodes:
            logger.info(f"跳过已知无效节点: {node_name}")
            skipped_count += 1
            continue
        nodes_to_test.append(node)

    logger.info(f"将测试 {len(nodes_to_test)} 个新节点（跳过 {skipped_count} 个已知无效节点）。")

    for i in range(0, len(nodes_to_test), BATCH_SIZE):
        batch = nodes_to_test[i:i + BATCH_SIZE]
        tasks = []
        for j, proxy_entry in enumerate(batch):
            async def test_with_semaphore(idx: int, entry: Dict[str, Any]):
                async with semaphore:
                    node_identifier = entry.get("name", "未知代理")
                    if not validate_proxy_entry(entry):
                        logger.info(f"[{i + idx + 1}/{len(nodes_to_test)}] ✗ 节点 {node_identifier} 格式无效，已跳过")
                        failure_reasons["invalid_format"] += 1
                        # 如果格式无效，也标记为无效，下次不再测试
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        return None
                    try:
                        clash_config = await generate_clash_config(entry, 0)
                        if await test_node(clash_config, node_identifier, i + idx + 1, len(nodes_to_test)):
                            return entry
                        logger.info(f"[{i + idx + 1}/{len(nodes_to_test)}] ✗ 节点 {node_identifier} 无效或延迟过高，已跳过")
                        # 标记为无效，下次不再测试
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        if "server disconnected" in str(entry).lower():
                            failure_reasons["server_disconnected"] += 1
                        elif "timeout" in str(entry).lower():
                            failure_reasons["timeout"] += 1
                        else:
                            failure_reasons["other"] += 1
                        return None
                    except Exception as e:
                        logger.error(f"[{i + idx + 1}/{len(nodes_to_test)}] 测试节点 {node_identifier} 失败: {e}")
                        failure_reasons["other"] += 1
                        # 标记为无效，下次不再测试
                        save_failed_node(Path(FAILED_NODES_FILE), node_identifier)
                        return None

            tasks.append(test_with_semaphore(j, proxy_entry))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_batch_proxy_dicts = [r for r in results if isinstance(r, dict) and r is not None]
        valid_proxy_dicts.extend(valid_batch_proxy_dicts)

        if valid_batch_proxy_dicts:
            with open(f"data/temp_valid_batch_{i//BATCH_SIZE + 1}.yaml", "w", encoding="utf-8") as f:
                yaml.safe_dump({"proxies": valid_batch_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，当前有效节点数: {len(valid_proxy_dicts)}")
        else:
            logger.info(f"批次 {i//BATCH_SIZE + 1} 完成，此批次无有效节点")

    if valid_proxy_dicts:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump({"proxies": valid_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
        logger.info(f"测试完成，保存 {len(valid_proxy_dicts)} 个有效节点到 {OUTPUT_FILE_PATH}")
    else:
        logger.warning("没有找到有效节点")

    logger.info(f"测试总结：总节点数: {len(nodes)}, 有效节点: {len(valid_proxy_dicts)}")
    logger.info(f"失败原因统计: {failure_reasons}")

if __name__ == "__main__":
    asyncio.run(main())
