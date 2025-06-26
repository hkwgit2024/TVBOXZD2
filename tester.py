import json
import random
import yaml
import aiohttp
import asyncio
from typing import Dict, Any, List
from pathlib import Path

# 全局变量：存储 Clash 基础配置模板
GLOBAL_CLASH_CONFIG_TEMPLATE: Dict[str, Any] | None = None

async def fetch_clash_base_config(url: str = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml") -> None:
    """
    从指定 URL 获取 Clash 基础配置模板并存储到全局变量。
    
    Args:
        url: Clash 基础配置模板的 URL
    """
    global GLOBAL_CLASH_CONFIG_TEMPLATE
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    raise ValueError(f"无法获取基础配置模板，HTTP 状态码: {response.status}")
                config_text = await response.text()
                GLOBAL_CLASH_CONFIG_TEMPLATE = yaml.safe_load(config_text)
                if not isinstance(GLOBAL_CLASH_CONFIG_TEMPLATE, dict):
                    raise ValueError("基础配置模板格式无效，必须为 YAML 字典")
    except aiohttp.ClientError as e:
        raise RuntimeError(f"获取 Clash 基础配置模板失败: {str(e)}")
    except yaml.YAMLError as e:
        raise ValueError(f"解析基础配置模板 YAML 失败: {str(e)}")

def validate_proxy_entry(proxy_entry: Dict[str, Any]) -> None:
    """
    验证代理节点的格式是否符合 Clash 要求。
    
    Args:
        proxy_entry: 代理节点配置字典
    
    Raises:
        ValueError: 如果代理节点格式无效
    """
    supported_protocols = ["ss", "vmess", "hysteria2", "vless", "trojan"]
    if not isinstance(proxy_entry, dict):
        raise ValueError("代理节点必须为字典格式")
    
    if "type" not in proxy_entry:
        raise ValueError("代理节点缺少 'type' 字段")
    
    if proxy_entry["type"] not in supported_protocols:
        raise ValueError(f"不支持的代理协议类型: {proxy_entry['type']}. 支持的协议: {supported_protocols}")
    
    if "name" not in proxy_entry:
        raise ValueError("代理节点缺少 'name' 字段")
    
    if "server" not in proxy_entry:
        raise ValueError("代理节点缺少 'server' 字段")
    
    if "port" not in proxy_entry:
        raise ValueError("代理节点缺少 'port' 字段")
    
    # 协议特定验证
    if proxy_entry["type"] == "ss":
        if "cipher" not in proxy_entry or "password" not in proxy_entry:
            raise ValueError("Shadowsocks 节点缺少 'cipher' 或 'password' 字段")
        if proxy_entry["cipher"] not in ["chacha20-ietf-poly1305", "aes-128-gcm", "2022-blake3-aes-128-gcm"]:
            raise ValueError(f"不支持的 Shadowsocks 加密方式: {proxy_entry['cipher']}")
    elif proxy_entry["type"] == "vmess":
        if "uuid" not in proxy_entry or "cipher" not in proxy_entry:
            raise ValueError("VMess 节点缺少 'uuid' 或 'cipher' 字段")
        if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
            raise ValueError("VMess WebSocket 节点缺少 'ws-opts' 字段")
    elif proxy_entry["type"] == "hysteria2":
        if "password" not in proxy_entry or "auth" not in proxy_entry:
            raise ValueError("Hysteria2 节点缺少 'password' 或 'auth' 字段")
        if proxy_entry.get("obfs") and "obfs-password" not in proxy_entry:
            raise ValueError("Hysteria2 节点启用了 obfs 但缺少 'obfs-password' 字段")
    elif proxy_entry["type"] == "vless":
        if "uuid" not in proxy_entry or "tls" not in proxy_entry:
            raise ValueError("VLESS 节点缺少 'uuid' 或 'tls' 字段")
        if proxy_entry.get("flow") == "xtls-rprx-vision" and "reality-opts" not in proxy_entry:
            raise ValueError("VLESS 节点使用 xtls-rprx-vision 流控但缺少 'reality-opts' 字段")
    elif proxy_entry["type"] == "trojan":
        if "password" not in proxy_entry:
            raise ValueError("Trojan 节点缺少 'password' 字段")
        if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
            raise ValueError("Trojan WebSocket 节点缺少 'ws-opts' 字段")

async def generate_clash_config(proxy_entry: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    """
    生成 Clash 配置文件，支持多种代理协议。

    Args:
        proxy_entry: 单个代理节点配置
        socks_port: SOCKS5 代理端口

    Returns:
        Dict[str, Any]: 生成的 Clash 配置字典

    Raises:
        ValueError: 如果基础模板未加载或代理节点无效
    """
    # 检查基础模板是否已加载
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        raise ValueError("Clash 基础配置模板未加载。请先调用 fetch_clash_base_config。")

    # 验证代理节点格式
    validate_proxy_entry(proxy_entry)

    # 深拷贝基础模板
    config = json.loads(json.dumps(GLOBAL_CLASH_CONFIG_TEMPLATE))

    # 设置基本配置
    config["port"] = random.randint(10000, 15000)
    config["socks-port"] = socks_port
    config["allow-lan"] = False
    config["mode"] = "rule"
    config["log-level"] = "info"

    # 初始化 proxies 列表并添加当前代理节点
    config.setdefault("proxies", []).clear()
    config["proxies"].append(proxy_entry)

    # 修复 proxy-groups 配置，避免 Reject 和 Direct 错误
    proxy_name = proxy_entry["name"]
    config["proxy-groups"] = [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": [proxy_name, "DIRECT", "REJECT"]
        }
    ]

    # 确保 rules 存在并包含默认规则
    if "rules" not in config or not isinstance(config["rules"], list):
        config["rules"] = [
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-SUFFIX,youtube.com,Proxy",
            "MATCH,Proxy"
        ]
    elif "MATCH,Proxy" not in config["rules"]:
        config["rules"].append("MATCH,Proxy")

    return config

async def save_clash_config(config: Dict[str, Any], filename: str) -> None:
    """
    将 Clash 配置保存为 YAML 文件。

    Args:
        config: Clash 配置字典
        filename: 输出文件名

    Raises:
        ValueError: 如果配置无效
        IOError: 如果文件写入失败
    """
    try:
        # 验证配置基本结构
        if not isinstance(config, dict):
            raise ValueError("配置必须为字典格式")
        if "proxies" not in config or not config["proxies"]:
            raise ValueError("配置缺少有效的 'proxies' 字段")
        if "proxy-groups" not in config or not config["proxy-groups"]:
            raise ValueError("配置缺少有效的 'proxy-groups' 字段")
        if "rules" not in config or not config["rules"]:
            raise ValueError("配置缺少有效的 'rules' 字段")

        # 保存为 YAML 文件
        Path(filename).parent.mkdir(parents=True, exist_ok=True)  # 确保目录存在
        with open(filename, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
    except yaml.YAMLError as e:
        raise ValueError(f"生成 YAML 文件失败: {str(e)}")
    except IOError as e:
        raise IOError(f"写入文件 {filename} 失败: {str(e)}")

async def load_proxies_from_file(file_path: str) -> List[Dict[str, Any]]:
    """
    从文件中加载代理节点列表。

    Args:
        file_path: 包含 proxies 的 YAML 文件路径

    Returns:
        List[Dict[str, Any]]: 代理节点列表

    Raises:
        ValueError: 如果文件格式无效
        IOError: 如果文件读取失败
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or "proxies" not in data:
            raise ValueError("文件格式无效，必须包含 'proxies' 字段")
        proxies = data["proxies"]
        if not isinstance(proxies, list):
            raise ValueError("'proxies' 必须为列表")
        for proxy in proxies:
            validate_proxy_entry(proxy)
        return proxies
    except yaml.YAMLError as e:
        raise ValueError(f"解析代理节点文件 {file_path} 失败: {str(e)}")
    except IOError as e:
        raise IOError(f"读取文件 {file_path} 失败: {str(e)}")

async def main():
    """
    主函数：加载代理节点并为每个节点生成配置文件。
    """
    try:
        # 加载基础模板
        await fetch_clash_base_config()

        # 加载代理节点（假设文件为 'proxies.yaml'，替换为您实际的文件路径）
        proxy_file = "proxies.yaml"
        proxies = await load_proxies_from_file(proxy_file)

        # 为每个代理节点生成配置文件
        for proxy_entry in proxies:
            socks_port = random.randint(1080, 2000)  # 随机分配 SOCKS 端口
            config = await generate_clash_config(proxy_entry, socks_port)
            output_file = f"clash_configs/clash_config_{proxy_entry['name']}.yaml"
            await save_clash_config(config, output_file)
            print(f"配置文件已保存到: {output_file}")

    except Exception as e:
        print(f"错误: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
