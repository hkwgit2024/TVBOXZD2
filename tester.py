import aiofiles
import asyncio
import base64
import logging
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import yaml
from pathlib import Path
import ssl
import certifi

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("test_nodes.log")
    ]
)
logger = logging.getLogger(__name__)

# 常量
MIHOMO_BIN_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.9/mihomo-linux-amd64-v1.18.9.gz"
MIHOMO_BIN_NAME = "mihomo"
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
TEST_URL = "http://1.1.1.1"
CONCURRENT_TESTS = 5
BASE_PORT = 7890
DATA_DIR = Path("data")
ALL_NODES_FILE = DATA_DIR / "all.txt"

# 确保数据目录存在
DATA_DIR.mkdir(exist_ok=True)

async def download_mihomo():
    """下载并解压 mihomo 二进制文件"""
    if not os.path.exists(MIHOMO_BIN_NAME):
        logger.info(f"下载 {MIHOMO_BIN_NAME}...")
        urllib.request.urlretrieve(MIHOMO_BIN_URL, f"{MIHOMO_BIN_NAME}.gz")
        subprocess.run(["gunzip", f"{MIHOMO_BIN_NAME}.gz"], check=True)
        os.chmod(MIHOMO_BIN_NAME, 0o755)
        logger.info(f"{MIHOMO_BIN_NAME} 下载并设置完成。")
    else:
        logger.info(f"{MIHOMO_BIN_NAME} 已存在，跳过下载。")

def parse_node_url(node_url):
    """解析节点 URL，支持多种协议"""
    try:
        parsed_url = urllib.parse.urlparse(node_url)
        scheme = parsed_url.scheme.lower()
        if scheme not in ["vmess", "ss", "trojan", "vless", "hysteria2", "hy2"]:
            logger.warning(f"不支持的协议: {scheme}")
            return None
        if scheme == "hy2":
            scheme = "hysteria2"  # 将 hy2 映射到 hysteria2
        if scheme == "trojan":
            return parse_trojan(node_url)
        elif scheme == "vmess":
            return parse_vmess(node_url)
        elif scheme == "ss":
            return parse_ss(node_url)
        elif scheme == "vless":
            return parse_vless(node_url)
        elif scheme == "hysteria2":
            return parse_hysteria2(node_url)
        return None
    except Exception as e:
        logger.error(f"解析 {node_url} 时出错: {e}")
        return None

def parse_trojan(node_url):
    """解析 Trojan 节点"""
    parsed = urllib.parse.urlparse(node_url)
    user_info = parsed.username
    hostname = parsed.hostname
    port = parsed.port
    query = urllib.parse.parse_qs(parsed.query)
    config = {
        "name": f"trojan-{hostname}:{port}",
        "type": "trojan",
        "server": hostname,
        "port": port,
        "password": user_info,
        "udp": True,
        "skip-cert-verify": False,
        "sni": query.get("sni", [hostname])[0]
    }
    return config

def parse_vmess(node_url):
    """解析 VMess 节点"""
    try:
        encoded_data = node_url.split("://")[1]
        decoded_data = base64.b64decode(encoded_data).decode()
        vmess_data = yaml.safe_load(decoded_data)
        config = {
            "name": vmess_data.get("ps", "vmess-node"),
            "type": "vmess",
            "server": vmess_data["add"],
            "port": int(vmess_data["port"]),
            "uuid": vmess_data["id"],
            "alterId": int(vmess_data.get("aid", 0)),
            "cipher": vmess_data.get("scy", "auto"),
            "udp": True,
            "tls": vmess_data.get("tls", "") == "tls",
            "skip-cert-verify": False,
            "network": vmess_data.get("net", "tcp")
        }
        return config
    except Exception as e:
        logger.error(f"解析 VMess 节点 {node_url} 时出错: {e}")
        return None

def parse_ss(node_url):
    """解析 Shadowsocks 节点"""
    try:
        parsed = urllib.parse.urlparse(node_url)
        user_info = parsed.username
        hostname = parsed.hostname
        port = parsed.port
        # 解码 user_info（base64 编码的 cipher:password）
        try:
            decoded_user_info = base64.b64decode(user_info + "==").decode()
            cipher, password = decoded_user_info.split(":")
        except ValueError:
            # 如果解码失败，尝试直接解析
            cipher, password = user_info.split(":")
        config = {
            "name": f"ss-{hostname}:{port}",
            "type": "ss",
            "server": hostname,
            "port": port,
            "cipher": cipher,
            "password": password,
            "udp": True
        }
        return config
    except Exception as e:
        logger.error(f"解析 Shadowsocks 节点 {node_url} 时出错: {e}")
        return None

def parse_vless(node_url):
    """解析 VLESS 节点"""
    try:
        parsed = urllib.parse.urlparse(node_url)
        user_info = parsed.username
        hostname = parsed.hostname
        port = parsed.port
        query = urllib.parse.parse_qs(parsed.query)
        config = {
            "name": f"vless-{hostname}:{port}",
            "type": "vless",
            "server": hostname,
            "port": port,
            "uuid": user_info,
            "udp": True,  
            "tls": query.get("security", [""])[0] in ["tls", "reality"],
            "skip-cert-verify": False,
            "network": query.get("type", ["tcp"])[0],
            "flow": query.get("flow", [""])[0] or None,  # 支持 flow 参数
            "public-key": query.get("pbk", [""])[0] or None,
            "fingerprint": query.get("fp", [""])[0] or None,
            "short-id": query.get("sid", [""])[0] or None,
            "servername": query.get("sni", [hostname])[0]
            }
        # 清理空值
        config = {k: v for k, v in config.items() if v is not None}
        return config
    except Exception as e:
        logger.error(f"解析 VLESS 节点 {node_url} 时出错: {e}")
        return None

def parse_hysteria2(node_url):
    """解析 Hysteria2 节点"""
    try:
        parsed = urllib.parse.urlparse(node_url)
        user_info = parsed.username
        hostname = parsed.hostname
        port = parsed.port
        query = urllib.parse.parse_qs(parsed.query)
        config = {
            "name": f"hysteria2-{hostname}:{port}",
            "type": "hysteria2",
            "server": hostname,
            "port": port,
            "password": user_info,
            "udp": True,
            "skip-cert-verify": query.get("insecure", ["0"])[0] == "1",
            "sni": query.get("sni", [hostname])[0]
        }
        return config
    except Exception as e:
        logger.error(f"解析 Hysteria2 节点 {node_url} 时出错: {e}")
        return None

def create_clash_config(node_url, port):
    """为单个节点生成 Clash 配置文件"""
    node_config = parse_node_url(node_url)
    if not node_config:
        return None

    config = {
        "port": port,
        "socks-port": port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{port + 1000}",
        "proxies": [node_config],
        "proxy-groups": [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": [node_config["name"]]
            }
        ],
        "rules": ["MATCH,Proxy"]
    }

    config_file = Path(f"config_{port}.yaml")
    try:
        with open(config_file, "w") as f:
            yaml.safe_dump(config, f, allow_unicode=True)
        return config_file
    except Exception as e:
        logger.error(f"生成配置文件 {config_file} 时出错: {e}")
        return None

async def mihomo_process(config_file, port):
    """启动 mihomo 进程并确保清理"""
    process = None
    try:
        logger.info(f"正在启动 {MIHOMO_BIN_NAME}，配置文件 {config_file}，端口 {port}...")
        process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", str(config_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        logger.info(f"{MIHOMO_BIN_NAME} 进程已启动 (PID: {process.pid})。给它一些时间进行初始化...")
        
        # 捕获 mihomo 输出
        async def log_mihomo_output():
            while process.poll() is None:
                line = await asyncio.to_thread(process.stdout.readline)
                if line:
                    logger.debug(f"mihomo stdout: {line.strip()}")
                line = await asyncio.to_thread(process.stderr.readline)
                if line:
                    logger.debug(f"mihomo stderr: {line.strip()}")
        
        asyncio.create_task(log_mihomo_output())
        await asyncio.sleep(10)  # 增加初始化时间
        yield process
    except Exception as e:
        logger.error(f"启动 mihomo 进程失败: {e}")
        raise
    finally:
        if process and process.poll() is None:
            logger.info(f"终止 {MIHOMO_BIN_NAME} 进程 (PID: {process.pid})...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning(f"进程 (PID: {process.pid}) 未正常终止，正在强制杀死...")
                process.kill()
        if config_file.exists():
            logger.info(f"删除配置文件 {config_file}...")
            config_file.unlink()

async def test_node_connectivity(node_url, current_port):
    """测试节点连接性"""
    logger.info(f"\n--- 正在测试节点: {node_url}，端口 {current_port} ---")
    
    temp_config_file = create_clash_config(node_url, current_port)
    if not temp_config_file:
        logger.warning(f"由于解析错误或不支持的协议，跳过节点: {node_url}。")
        return None

    try:
        async with mihomo_process(temp_config_file, current_port) as process:
            curl_command = [
                "curl",
                "--socks5-hostname", f"127.0.0.1:{current_port}",
                TEST_URL,
                "--max-time", "30",
                "--silent", "--output", "/dev/null",
                "--fail"
            ]
            logger.debug(f"Curl 命令: {' '.join(curl_command)}")
            result = await asyncio.to_thread(subprocess.run, curl_command, capture_output=True, text=True)
            
            logger.debug(f"Curl stdout: {result.stdout}")
            logger.debug(f"Curl stderr: {result.stderr}")

            if result.returncode == 0:
                logger.info(f"节点 {node_url} 已连接。")
                return node_url
            logger.warning(f"节点 {node_url} 连接失败 (curl退出码: {result.returncode})。")
            return None
    except Exception as e:
        logger.error(f"测试 {node_url} 时发生错误: {e}")
        return None

async def test_nodes(nodes):
    """并发测试节点"""
    working_nodes = []
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)
    
    async def test_with_semaphore(node_url, port):
        async with semaphore:
            return await test_node_connectivity(node_url, port)

    tasks = []
    for i, node_url in enumerate(nodes):
        port = BASE_PORT + (i % CONCURRENT_TESTS)
        tasks.append(test_with_semaphore(node_url, port))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    working_nodes = [node for node in results if node and not isinstance(node, Exception)]
    
    return working_nodes

async def save_working_nodes(working_nodes):
    """保存可用节点到文件"""
    if not working_nodes:
        logger.warning("没有找到可用节点，跳过写入空文件。")
        return

    async with aiofiles.open(ALL_NODES_FILE, "w") as f:
        for node in working_nodes:
            await f.write(f"{node}\n")
    logger.info(f"可用节点已保存到 {ALL_NODES_FILE}")

async def main():
    """主函数"""
    logger.info("开始运行节点测试脚本...")
    
    await download_mihomo()
    
    logger.info(f"从 {NODE_LIST_URL} 获取节点列表...")
    context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(NODE_LIST_URL, context=context) as response:
        nodes = response.read().decode().splitlines()
    
    logger.info(f"共找到 {len(nodes)} 个节点。")
    
    working_nodes = await test_nodes(nodes)
    logger.info(f"找到的可用节点数: {len(working_nodes)}")
    
    await save_working_nodes(working_nodes)

if __name__ == "__main__":
    asyncio.run(main())
