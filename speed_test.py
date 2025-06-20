#!/usr/bin/env python3

import requests
import re
import base64
import json
import yaml
import subprocess
import time
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs
from hashlib import md5

# 常量定义
LOG_FILE = "node_connectivity_results.log"
OUTPUT_DIR = "data"
SUCCESS_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
FAILED_FILE = os.path.join(OUTPUT_DIR, "failed_nodes.txt")
UNPARSED_FILE = "unparsed_nodes.log"
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    # 可添加其他节点来源 URL
]
TIMEOUT = 10  # 测试超时时间（秒）
MAX_WORKERS = 50  # 并发测试线程数（根据 GitHub Actions 性能调整）
RETRY_COUNT = 2  # 每个节点重试次数

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8", mode="a"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 加载已知失败节点
def load_failed_nodes():
    failed_nodes = set()
    if os.path.exists(FAILED_FILE):
        with open(FAILED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # 使用 MD5 哈希去重，兼容格式差异
                    node_hash = md5(line.encode("utf-8")).hexdigest()
                    failed_nodes.add(node_hash)
    return failed_nodes

# 检查依赖
def check_dependencies():
    deps = ["sing-box", "xray", "dig"]
    for dep in deps:
        try:
            subprocess.run([dep, "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error(f"依赖 '{dep}' 未找到，请确保已安装。")
            exit(1)

# 解析明文节点
def parse_plain_node(node_link):
    pattern = r"^(hysteria2|vless|vmess|trojan|ss)://(.+@)?([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+)(\?.*)?$"
    match = re.match(pattern, node_link)
    if match:
        protocol, _, hostname_or_ip, port, params = match.groups()
        return {"protocol": protocol, "host": hostname_or_ip, "port": int(port), "params": params or "", "raw": node_link}
    return None

# 解析 Base64 节点
def parse_base64_node(node_link):
    match = re.match(r"^(ss|vmess)://([A-Za-z0-9+/=]+)", node_link)
    if not match:
        return None
    protocol, base64_part = match.groups()
    try:
        decoded = base64.urlsafe_b64decode(base64_part.replace("_", "+").replace("-", "/")).decode("utf-8")
    except Exception as e:
        logger.warning(f"Base64 解码失败: {node_link} ({e})")
        return None

    if protocol == "vmess":
        try:
            vmess_data = json.loads(decoded)
            return {
                "protocol": "vmess",
                "host": vmess_data.get("add"),
                "port": int(vmess_data.get("port")),
                "id": vmess_data.get("id", ""),
                "params": "",
                "raw": node_link
            }
        except json.JSONDecodeError:
            logger.warning(f"VMess JSON 解析失败: {node_link}")
            return None
    elif protocol == "ss":
        match = re.match(r"(.+)@([0-9a-zA-Z.-]+|\[[0-9a-fA-F:]+\]):([0-9]+)", decoded)
        if match:
            method_password, host, port = match.groups()
            return {"protocol": "ss", "host": host, "port": int(port), "method_password": method_password, "raw": node_link}
        logger.warning(f"SS 节点解析失败: {node_link}")
        return None
    return None

# 解析 YAML 节点
def parse_yaml_node(node_content):
    try:
        yaml_data = yaml.safe_load(node_content)
        server = yaml_data.get("server")
        port = yaml_data.get("port")
        protocol = yaml_data.get("protocol", "unknown")
        if server and port:
            # 转换为标准 URI 格式以兼容客户端
            raw = f"{protocol}://{server}:{port}"
            return {"protocol": protocol, "host": server, "port": int(port), "params": "", "raw": raw}
        logger.warning(f"YAML 节点缺少必要字段: {node_content}")
        return None
    except yaml.YAMLError:
        logger.warning(f"YAML 解析失败: {node_content}")
        return None

# 综合解析函数
def parse_node(node_link):
    # 跳过空行、注释和分隔符
    if not node_link or node_link.startswith("#") or node_link.startswith("-"):
        return None
    # 检查是否为已知失败节点
    node_hash = md5(node_link.encode("utf-8")).hexdigest()
    if node_hash in load_failed_nodes():
        logger.info(f"跳过已知失败节点: {node_link}")
        return None
    # 尝试明文解析
    result = parse_plain_node(node_link)
    if result:
        return result
    # 尝试 Base64 解析
    result = parse_base64_node(node_link)
    if result:
        return result
    # 尝试 YAML 解析
    result = parse_yaml_node(node_link)
    if result:
        return result
    # 记录无法解析的节点
    with open(UNPARSED_FILE, "a", encoding="utf-8") as f:
        f.write(f"{node_link}\n")
    logger.warning(f"无法解析节点: {node_link}")
    return None

# 解析域名
def resolve_domain(host):
    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", host) or re.match(r"^\[[0-9a-fA-F:]+\]$", host):
        return host
    try:
        result = subprocess.run(["dig", "+short", "-t", "A", host, "@8.8.8.8"], capture_output=True, text=True)
        ip = result.stdout.strip().split("\n")[0]
        if not ip:
            result = subprocess.run(["dig", "+short", "-t", "AAAA", host, "@8.8.8.8"], capture_output=True, text=True)
            ip = result.stdout.strip().split("\n")[0]
        if ip:
            logger.info(f"域名解析: {host} -> {ip}")
            return ip
        logger.warning(f"无法解析域名: {host}")
        return None
    except subprocess.CalledProcessError:
        logger.warning(f"域名解析失败: {host}")
        return None

# 测试节点（使用 Sing-Box 或 Xray Core）
def test_node(node_link):
    parsed = parse_node(node_link)
    if not parsed:
        return None, node_link

    protocol = parsed["protocol"]
    host = parsed["host"]
    port = parsed["port"]
    raw_node = parsed["raw"]

    # 解析域名
    ip = resolve_domain(host)
    if not ip:
        return None, node_link
    target_host = f"[{ip}]" if ":" in ip else ip

    # 准备 Sing-Box 配置
    config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "http", "listen": "127.0.0.1", "port": 1080}],
        "outbounds": [{"type": protocol, "server": ip, "port": port}]
    }

    # 根据协议补充配置
    if protocol == "ss":
        method_password = parsed.get("method_password", "").split(":")
        if len(method_password) == 2:
            config["outbounds"][0]["method"] = method_password[0]
            config["outbounds"][0]["password"] = method_password[1]
    elif protocol == "vmess":
        config["outbounds"][0]["uuid"] = parsed.get("id", "")
    elif protocol == "vless":
        config["outbounds"][0]["uuid"] = parse_qs(urlparse(node_link).query).get("uuid", [""])[0]
    elif protocol == "trojan":
        config["outbounds"][0]["password"] = parse_qs(urlparse(node_link).query).get("password", [""])[0]
    elif protocol == "hysteria2":
        config["outbounds"][0]["password"] = parse_qs(urlparse(node_link).query).get("auth", [""])[0]

    # 保存临时配置文件
    temp_config = f"/tmp/sing-box-config-{time.time()}.json"
    with open(temp_config, "w", encoding="utf-8") as f:
        json.dump(config, f)

    # 测试连接（优先使用 Sing-Box）
    for attempt in range(RETRY_COUNT):
        try:
            proc = subprocess.Popen(["sing-box", "run", "-c", temp_config], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # 等待客户端启动
            result = subprocess.run(
                ["curl", "-x", "http://127.0.0.1:1080", "--max-time", str(TIMEOUT), "http://example.com"],
                capture_output=True,
                text=True
            )
            proc.terminate()
            os.remove(temp_config)
            if result.returncode == 0:
                logger.info(f"成功连接到 {target_host}:{port} ({protocol})")
                return raw_node, None
            else:
                logger.warning(f"尝试 {attempt + 1}/{RETRY_COUNT} 失败: {target_host}:{port} ({protocol})")
        except subprocess.CalledProcessError:
            logger.warning(f"Sing-Box 测试失败，尝试 {attempt + 1}/{RETRY_COUNT}: {node_link}")
            os.remove(temp_config)

    # 备选：使用 Xray Core
    for attempt in range(RETRY_COUNT):
        try:
            proc = subprocess.Popen(["xray", "run", "-c", temp_config], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            result = subprocess.run(
                ["curl", "-x", "http://127.0.0.1:1080", "--max-time", str(TIMEOUT), "http://example.com"],
                capture_output=True,
                text=True
            )
            proc.terminate()
            if result.returncode == 0:
                logger.info(f"Xray Core 成功连接到 {target_host}:{port} ({protocol})")
                return raw_node, None
            else:
                logger.warning(f"Xray Core 尝试 {attempt + 1}/{RETRY_COUNT} 失败: {target_host}:{port} ({protocol})")
        except subprocess.CalledProcessError:
            logger.warning(f"Xray Core 测试失败，尝试 {attempt + 1}/{RETRY_COUNT}: {node_link}")
        finally:
            if os.path.exists(temp_config):
                os.remove(temp_config)
    return None, node_link

# 主逻辑
def main():
    logger.info("开始节点连接性测试...")
    logger.info(f"测试时间: {datetime.now()}")

    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 检查依赖
    check_dependencies()

    # 下载并合并节点
    all_nodes = set()
    for url in NODE_SOURCES:
        logger.info(f"正在下载: {url}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            nodes = response.text.splitlines()
            all_nodes.update(nodes)
        except requests.RequestException as e:
            logger.warning(f"无法下载 {url}: {e}")

    if not all_nodes:
        logger.error("未能下载任何节点配置文件。")
        exit(1)

    logger.info(f"共计 {len(all_nodes)} 个唯一节点，开始测试...")

    # 并行测试节点
    success_nodes = []
    failed_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(test_node, all_nodes)
        for success, failed in results:
            if success:
                success_nodes.append(success)
            elif failed:
                failed_nodes.append(failed)

    # 追加保存成功节点
    with open(SUCCESS_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n# Successful Nodes (Appended at {datetime.now()})\n")
        f.write("-------------------------------------\n")
        for node in success_nodes:
            f.write(f"{node}\n")

    # 追加保存失败节点
    with open(FAILED_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n# Failed Nodes (Appended at {datetime.now()})\n")
        f.write("-------------------------------------\n")
        for node in failed_nodes:
            f.write(f"{node}\n")

    logger.info(f"成功节点已追加到 {SUCCESS_FILE}，共 {len(success_nodes)} 个")
    logger.info(f"失败节点已追加到 {FAILED_FILE}，共 {len(failed_nodes)} 个")
    logger.info("测试完成。")

if __name__ == "__main__":
    main()
