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
import contextlib # 导入 contextlib 模块

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
TEST_URL = "http://1.1.1.1" # 建议使用更稳定的测试地址，如 "http://www.gstatic.com/generate_204"
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
        try:
            await asyncio.to_thread(urllib.request.urlretrieve, MIHOMO_BIN_URL, f"{MIHOMO_BIN_NAME}.gz")
            await asyncio.to_thread(subprocess.run, ["gunzip", "-f", f"{MIHOMO_BIN_NAME}.gz"], check=True) # 添加 -f 强制解压
            await asyncio.to_thread(os.chmod, MIHOMO_BIN_NAME, 0o755)
            logger.info(f"{MIHOMO_BIN_NAME} 下载并设置完成。")
        except Exception as e:
            logger.exception(f"下载或解压 {MIHOMO_BIN_NAME} 时出错: {e}")
            sys.exit(1) # 如果下载失败，脚本应退出
    else:
        logger.info(f"{MIHOMO_BIN_NAME} 已存在，跳过下载。")
        await asyncio.to_thread(os.chmod, MIHOMO_BIN_NAME, 0o755) # 确保权限正确

def parse_node_url(node_url):
    """解析节点 URL，支持多种协议"""
    try:
        parsed_url = urllib.parse.urlparse(node_url)
        scheme = parsed_url.scheme.lower()
        if scheme not in ["vmess", "ss", "trojan", "vless", "hysteria2", "hy2"]:
            logger.warning(f"不支持的协议: {scheme}")
            return None
        if scheme == "hy2":
            scheme = "hysteria2" # 将 hy2 映射到 hysteria2
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
        "skip-cert-verify": query.get("allowInsecure", ["0"])[0] == "1", # 修复 allowInsecure 参数
        "sni": query.get("sni", [hostname])[0]
    }
    return config

def parse_vmess(node_url):
    """解析 VMess 节点"""
    try:
        encoded_data = node_url.split("://")[1]
        # 添加填充，确保 Base64 解码正确
        encoded_data = encoded_data + '=' * (-len(encoded_data) % 4)
        decoded_data = base64.b64decode(encoded_data).decode()
        vmess_data = yaml.safe_load(decoded_data) # VMess 配置通常是 JSON，这里使用 yaml.safe_load 可能会有问题，但如果内容是兼容的 YAML 格式则无妨
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
            "skip-cert-verify": vmess_data.get("v", "") == "1" or vmess_data.get("allowInsecure", False), # 兼容 VLESS 的 skip-cert-verify
            "network": vmess_data.get("net", "tcp")
        }
        # 处理 ws-opts 和 grpc-opts
        if config["network"] == "ws":
            config["ws-opts"] = {
                "path": vmess_data.get("path", "/"),
                "headers": {"Host": vmess_data.get("host", vmess_data.get("add"))}
            }
        elif config["network"] == "grpc":
            config["grpc-opts"] = {
                "serviceName": vmess_data.get("path", ""),
                "grpcMode": vmess_data.get("grpcMode", "gun") # 默认 gun
            }
        return config
    except Exception as e:
        logger.error(f"解析 VMess 节点 {node_url} 时出错: {e}")
        return None

def parse_ss(node_url):
    """解析 Shadowsocks 节点"""
    try:
        parsed = urllib.parse.urlparse(node_url)
        user_info_encoded = parsed.username
        hostname = parsed.hostname
        port = parsed.port

        # Shadowsocks 的 user_info 可能是 base64 编码的 "cipher:password"
        decoded_user_info = ""
        try:
            decoded_user_info = base64.b64decode(user_info_encoded + "==").decode()
        except (base64.binascii.Error, UnicodeDecodeError):
            # 如果解码失败，可能是未编码的，直接使用
            decoded_user_info = user_info_encoded
        
        cipher, password = "auto", decoded_user_info
        if ":" in decoded_user_info:
            cipher, password = decoded_user_info.split(":", 1) # 只分割一次

        config = {
            "name": f"ss-{hostname}:{port}",
            "type": "ss",
            "server": hostname,
            "port": port,
            "cipher": cipher,
            "password": password,
            "udp": True
        }
        # 处理插件
        query = urllib.parse.parse_qs(parsed.query)
        plugin = query.get('plugin', [''])[0]
        plugin_opts = query.get('plugin_opts', [''])[0]
        if plugin:
            config["plugin"] = plugin
            if plugin_opts:
                config["plugin-opts"] = plugin_opts
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
        
        security = query.get("security", [""])[0]
        tls_enabled = security in ["tls", "reality"]

        config = {
            "name": f"vless-{hostname}:{port}",
            "type": "vless",
            "server": hostname,
            "port": port,
            "uuid": user_info,
            "udp": True,
            "tls": tls_enabled,
            "skip-cert-verify": query.get("allowInsecure", ["0"])[0] == "1",
            "network": query.get("type", ["tcp"])[0],
            "servername": query.get("sni", [hostname])[0] # Clash.Meta 使用 servername 而非 sni
        }
        
        # 处理可选参数
        flow = query.get("flow", [""])[0]
        if flow:
            config["flow"] = flow
        
        if security == "reality":
            config["reality-opts"] = {
                "public-key": query.get("pbk", [""])[0],
                "short-id": query.get("sid", [""])[0] or None,
                "fingerprint": query.get("fp", [""])[0] or None
            }
        
        if config["network"] == "ws":
            config["ws-opts"] = {
                "path": query.get("path", ["/"])[0],
                "headers": {"Host": query.get("host", [hostname])[0]}
            }
        elif config["network"] == "grpc":
            config["grpc-opts"] = {
                "serviceName": query.get("serviceName", [""])[0],
                "grpcMode": query.get("grpcMode", ["gun"])[0]
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
            "tls": True, # Hysteria2 总是使用 TLS
            "skip-cert-verify": query.get("insecure", ["0"])[0] == "1",
            "sni": query.get("sni", [hostname])[0]
        }
        # 处理可选参数
        obfs = query.get('obfs', [None])[0]
        if obfs:
            config['obfs'] = obfs
            config['obfs-password'] = query.get('obfs-password', [None])[0]

        alpn = query.get('alpn', [None])[0]
        if alpn:
            config['alpn'] = alpn.split(',') # ALPN 可以是逗号分隔的列表

        return config
    except Exception as e:
        logger.error(f"解析 Hysteria2 节点 {node_url} 时出错: {e}")
        return None

def create_clash_config(node_url, port):
    """为单个节点生成 Clash 配置文件"""
    node_config = parse_node_url(node_url)
    if not node_config:
        return None

    # 给代理一个唯一的名称，防止冲突
    proxy_name = node_config.get("name", f"proxy_{port}_{hash(node_url) % 10000}")
    node_config["name"] = proxy_name

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
                "proxies": [proxy_name]
            }
        ],
        "rules": ["MATCH,Proxy"]
    }

    config_file = Path(f"config_{port}.yaml")
    try:
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        return config_file
    except Exception as e:
        logger.error(f"生成配置文件 {config_file} 时出错: {e}")
        return None

# 将 mihomo_process 定义为异步上下文管理器
@contextlib.asynccontextmanager # 更正：从 contextlib 导入
async def mihomo_process(config_file, port):
    """启动 mihomo 进程并确保清理"""
    process = None
    try:
        logger.info(f"正在启动 {MIHOMO_BIN_NAME}，配置文件 {config_file}，端口 {port}...")
        # 包装 Popen 以在单独线程中运行，防止其内部同步异常阻塞事件循环
        process = await asyncio.to_thread(subprocess.Popen,
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
                try:
                    stdout_line = await asyncio.to_thread(process.stdout.readline)
                    if stdout_line:
                        logger.debug(f"mihomo stdout: {stdout_line.strip()}")
                    stderr_line = await asyncio.to_thread(process.stderr.readline)
                    if stderr_line:
                        logger.debug(f"mihomo stderr: {stderr_line.strip()}")
                except ValueError: # Stream might close
                    break
                await asyncio.sleep(0.01) # 短暂休眠以避免CPU占用过高
            logger.debug(f"Mihomo output logging for PID {process.pid} stopped. Return code: {process.returncode}")

        asyncio.create_task(log_mihomo_output())
        await asyncio.sleep(10) # 增加初始化时间，确保服务完全启动
        yield process
    except Exception as e:
        # 使用 logger.exception 打印完整堆栈信息
        logger.exception(f"启动 mihomo 进程失败: {e}")
        raise # 重新抛出异常，让外部调用者知道启动失败
    finally:
        if process and process.poll() is None:
            logger.info(f"终止 {MIHOMO_BIN_NAME} 进程 (PID: {process.pid})...")
            process.terminate()
            try:
                # 包装 blocking wait with asyncio.to_thread
                await asyncio.to_thread(process.wait, timeout=5)
                logger.info(f"{MIHOMO_BIN_NAME} 进程已终止 (PID: {process.pid})")
            except subprocess.TimeoutExpired:
                logger.warning(f"进程 (PID: {process.pid}) 未正常终止，正在强制杀死...")
                process.kill()
        elif process:
             logger.info(f"{MIHOMO_BIN_NAME} 进程 (PID: {process.pid}) 已退出，返回码: {process.returncode}")

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
        # async with 语句会调用 mihomo_process 的 __aenter__ 和 __aexit__
        async with mihomo_process(temp_config_file, current_port) as process:
            # 检查 mihomo 进程是否仍在运行
            if process.poll() is not None:
                logger.warning(f"Mihomo 进程 (PID: {process.pid}) 意外退出，返回码: {process.returncode}。跳过测试 {node_url}。")
                # 可以尝试读取 stderr 进一步诊断
                stderr_output = await asyncio.to_thread(process.stderr.read)
                if stderr_output:
                    logger.warning(f"Mihomo stderr for {node_url}:\n{stderr_output}")
                return None

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
        logger.exception(f"测试 {node_url} 时发生错误: {e}") # 记录完整异常
        return None

async def test_nodes(nodes):
    """并发测试节点"""
    working_nodes = []
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)
    
    # 使用队列分配端口，确保每个并发任务都有独立的端口
    port_queue = asyncio.Queue()
    for i in range(CONCURRENT_TESTS):
        await port_queue.put(BASE_PORT + i)

    async def test_with_semaphore(node_url):
        async with semaphore:
            current_port = await port_queue.get() # 获取一个可用端口
            try:
                result = await test_node_connectivity(node_url, current_port)
                return result
            finally:
                await port_queue.put(current_port) # 确保端口被释放回队列

    tasks = [test_with_semaphore(node) for node in nodes]
    
    # 打印进度
    for i, future in enumerate(asyncio.as_completed(tasks)):
        result = await future
        if result:
            working_nodes.append(result)
        logger.info(f"已处理 {i+1}/{len(nodes)} 个节点。")
    
    return working_nodes

async def save_working_nodes(working_nodes):
    """保存可用节点到文件"""
    if not working_nodes:
        logger.warning("没有找到可用节点，跳过写入空文件。")
        # 移除可能存在的旧文件，确保文件不存在如果没可用节点
        if ALL_NODES_FILE.exists():
            await asyncio.to_thread(ALL_NODES_FILE.unlink)
        return

    async with aiofiles.open(ALL_NODES_FILE, "w", encoding="utf-8") as f:
        for node in working_nodes:
            await f.write(f"{node}\n")
    logger.info(f"可用节点已保存到 {ALL_NODES_FILE}")

async def main():
    """主函数"""
    logger.info("开始运行节点测试脚本...")
    
    await download_mihomo()
    
    logger.info(f"从 {NODE_LIST_URL} 获取节点列表...")
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        # 包装 urlopen 和 read 以在单独线程中运行
        with await asyncio.to_thread(urllib.request.urlopen, NODE_LIST_URL, context=context) as response:
            nodes_raw = await asyncio.to_thread(response.read)
            nodes = nodes_raw.decode('utf-8').splitlines()
    except Exception as e:
        logger.exception(f"下载节点列表时出错: {e}")
        sys.exit(1) # 如果无法下载节点列表，则退出

    logger.info(f"共找到 {len(nodes)} 个节点。")
    
    working_nodes = await test_nodes(nodes)
    logger.info(f"\n--- 脚本执行完成 ---")
    logger.info(f"总共处理的节点数: {len(nodes)}")
    logger.info(f"找到的可用节点数: {len(working_nodes)}")
    
    await save_working_nodes(working_nodes)

if __name__ == "__main__":
    asyncio.run(main())
