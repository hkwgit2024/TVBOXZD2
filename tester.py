import asyncio
import base64
import json
import logging
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import requests
import yaml

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 常量
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
MIHOMO_DOWNLOAD_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.11/mihomo-linux-amd64-v1.19.11.gz"
MIHOMO_BIN_NAME = "mihomo"
CONFIG_FILE = Path("config.yaml") # 这将在每次测试时被覆盖。
OUTPUT_DIR = Path("data")
OUTPUT_FILE = OUTPUT_DIR / "all.txt"
CLASH_BASE_PORT = 7890 # Clash.Meta 本地代理的起始端口
TEST_URL = "http://www.gstatic.com/generate_204" # 用于测试连接的URL，从google.com更改为更可靠的地址。
CONCURRENT_TESTS = 10 # 并发测试的节点数量

def validate_url(url):
    """验证URL格式是否正确。"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def download_file(url, destination):
    """从URL下载文件到指定位置并显示进度。
    Args:
        url (str): 要下载的URL。
        destination (pathlib.Path): 文件应保存的Path对象。
    """
    if not validate_url(url):
        logger.error(f"无效URL: {url}")
        return False

    logger.info(f"正在从 {url} 下载到 {destination}...")
    try:
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0

            with destination.open('wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    if total_size > 0:
                        progress = (downloaded_size / total_size) * 100
                        sys.stdout.write(
                            f"\r下载中: {downloaded_size / (1024*1024):.2f}MB / "
                            f"{total_size / (1024*1024):.2f}MB ({progress:.1f}%)"
                        )
                    else:
                        sys.stdout.write(f"\r下载中: {downloaded_size / (1024*1024):.2f}MB")
                    sys.stdout.flush()
                sys.stdout.write("\n")
                logger.info("下载完成。")
                return True
    except requests.RequestException as e:
        logger.error(f"下载 {url} 时出错: {e}")
        return False

def setup_mihomo():
    """下载、解压并设置Mihomo二进制文件。"""
    logger.info("正在检查Mihomo二进制文件设置...")
    bin_path = Path(MIHOMO_BIN_NAME)
    if bin_path.exists():
        logger.info(f"{MIHOMO_BIN_NAME} 已存在。")
        bin_path.chmod(0o755)
        return

    archive_filename = Path(MIHOMO_DOWNLOAD_URL).name
    archive_path = Path(archive_filename)
    
    if not download_file(MIHOMO_DOWNLOAD_URL, archive_path):
        logger.error("下载Mihomo二进制文件失败。")
        sys.exit(1)

    logger.info(f"正在解压 {archive_filename}...")
    try:
        subprocess.run(["gunzip", "-f", str(archive_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        extracted_name = archive_path.with_suffix('')

        found_extracted = False
        for p_name in [extracted_name.name, MIHOMO_BIN_NAME, "clash", "clash-linux-amd64"]:
            p_path = Path(p_name)
            if p_path.exists() and not p_path.is_dir():
                p_path.rename(MIHOMO_BIN_NAME)
                logger.info(f"已将 {p_name} 重命名为 {MIHOMO_BIN_NAME}")
                found_extracted = True
                break
        
        if not found_extracted:
            logger.error("在常见名称中找不到解压后的Mihomo二进制文件。请检查归档内容。")
            sys.exit(1)

        bin_path.chmod(0o755)
        logger.info(f"{MIHOMO_BIN_NAME} 已设置并可执行。")
    except subprocess.CalledProcessError as e:
        logger.error(f"解压时出错: {e.output.decode()}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"设置Mihomo时发生意外错误: {e}")
        sys.exit(1)

def download_and_parse_nodes(url):
    """下载并解析节点配置。"""
    if not validate_url(url):
        logger.error(f"无效的节点列表URL: {url}")
        return []

    logger.info(f"正在从 {url} 下载节点列表")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        content = response.text
    except requests.RequestException as e:
        logger.error(f"下载节点列表时出错: {e}")
        return []

    protocols = ["hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"]
    nodes = set()
    for line in content.splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            nodes.add(line)
    logger.info(f"找到 {len(nodes)} 个唯一节点。")
    return list(nodes)

def parse_vmess(node_url):
    """解析vmess节点配置。"""
    try:
        vmess_b64 = node_url[len("vmess://"):]
        # 如果需要，添加填充
        vmess_b64 = vmess_b64 + '=' * (-len(vmess_b64) % 4)
        decoded_vmess = json.loads(base64.b64decode(vmess_b64).decode('utf-8'))
        return {
            "type": "vmess",
            "server": decoded_vmess.get("add"),
            "port": int(decoded_vmess.get("port")),
            "uuid": decoded_vmess.get("id"),
            "alterId": int(decoded_vmess.get("aid", 0)),
            "cipher": decoded_vmess.get("scy", "auto"),
            "network": decoded_vmess.get("net", "tcp"),
            "tls": decoded_vmess.get("tls", "") == "tls",
            "skip-cert-verify": decoded_vmess.get("v", "") == "1" or decoded_vmess.get("allowInsecure", False),
            "ws-opts": {
                "path": decoded_vmess.get("path", "/"),
                "headers": {"Host": decoded_vmess.get("host", decoded_vmess.get("add"))}
            } if decoded_vmess.get("net") == "ws" else {},
            "grpc-opts": {
                "serviceName": decoded_vmess.get("path", ""),
                "grpcMode": "gun"
            } if decoded_vmess.get("net") == "grpc" else {}
        }
    except (json.JSONDecodeError, base64.binascii.Error, ValueError) as e:
        logger.error(f"解析vmess节点 {node_url} 时出错: {e}")
        return None

def parse_ss(node_url):
    """解析shadowsocks节点配置。"""
    try:
        parsed_url = urlparse(node_url)
        method_password_encoded = parsed_url.username
        if not method_password_encoded:
            logger.error(f"无效的shadowsocks节点格式 (缺少方法/密码): {node_url}")
            return None

        method_password = ""
        try:
            method_password = base64.b64decode(method_password_encoded + '=' * (-len(method_password_encoded) % 4)).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            method_password = method_password_encoded

        method, password = "auto", method_password
        if ':' in method_password:
            method, password = method_password.split(':', 1)

        params = parse_qs(parsed_url.query)
        if not params and parsed_url.fragment:
            params = parse_qs(parsed_url.fragment)

        plugin = params.get('plugin', [''])[0]
        plugin_opts = params.get('plugin_opts', [''])[0]

        ss_proxy = {
            "type": "ss",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "cipher": method,
            "password": password,
        }
        if plugin:
            ss_proxy["plugin"] = plugin
            if plugin_opts:
                ss_proxy["plugin-opts"] = plugin_opts

        return ss_proxy
    except (ValueError, AttributeError) as e:
        logger.error(f"解析ss节点 {node_url} 时出错: {e}")
        return None

def parse_trojan(node_url):
    """解析trojan节点配置。"""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        return {
            "type": "trojan",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "password": parsed_url.username,
            "tls": True,
            "sni": params.get('sni', [parsed_url.hostname])[0],
            "skip-cert-verify": params.get('allowInsecure', ['0'])[0] == '1'
        }
    except (ValueError, AttributeError) as e:
        logger.error(f"解析trojan节点 {node_url} 时出错: {e}")
        return None

def parse_vless(node_url):
    """解析vless节点配置。"""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        network = params.get('type', ['tcp'])[0]
        tls_enabled = params.get('security', [''])[0] == 'tls'
        ws_path = params.get('path', ['/'])[0]
        ws_headers_host = params.get('host', [parsed_url.hostname])[0]
        flow = params.get('flow', [None])[0]
        sni = params.get('sni', [parsed_url.hostname])[0]
        skip_cert_verify = params.get('allowInsecure', ['0'])[0] == '1'

        vless_proxy = {
            "type": "vless",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "uuid": parsed_url.username,
            "network": network,
            "tls": tls_enabled,
            "sni": sni,
            "skip-cert-verify": skip_cert_verify,
            "udp": True
        }
        if flow:
            vless_proxy["flow"] = flow

        if network == "ws":
            vless_proxy["ws-opts"] = {
                "path": ws_path,
                "headers": {"Host": ws_headers_host}
            }
        elif network == "grpc":
            grpc_mode = params.get('grpcMode', ['gun'])[0]
            service_name = params.get('serviceName', [''])[0]
            vless_proxy["grpc-opts"] = {
                "grpcMode": grpc_mode,
                "serviceName": service_name
            }
        return vless_proxy
    except (ValueError, AttributeError) as e:
        logger.error(f"解析vless节点 {node_url} 时出错: {e}")
        return None

def parse_hysteria2(node_url):
    """解析hysteria2节点配置。"""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        return {
            "type": "hysteria2",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "password": parsed_url.username,
            "tls": True,
            "skip-cert-verify": params.get('insecure', ['0'])[0] == '1',
            "obfs": params.get('obfs', [None])[0],
            "obfs-password": params.get('obfs-password', [None])[0],
            "alpn": params.get('alpn', [None])[0],
            "sni": params.get('sni', [parsed_url.hostname])[0]
        }
    except (ValueError, AttributeError) as e:
        logger.error(f"解析hysteria2节点 {node_url} 时出错: {e}")
        return None

def create_clash_config(node_url, port):
    """为单个节点创建基本的Clash.Meta配置。"""
    proxy_name = f"proxy-{hash(node_url) % 100000}"
    config = {
        "port": port, # 使用动态分配的端口
        "mode": "direct",
        "log-level": "debug",
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "proxies": [],
        "proxy-groups": [{"name": "select", "type": "select", "proxies": [proxy_name]}],
        "rules": ["MATCH,select"]
    }

    parsers = {
        "vmess://": parse_vmess,
        "ss://": parse_ss,
        "trojan://": parse_trojan,
        "vless://": parse_vless,
        "hysteria2://": parse_hysteria2
    }

    for protocol, parser in parsers.items():
        if node_url.startswith(protocol):
            proxy = parser(node_url)
            if proxy:
                proxy["name"] = proxy_name
                config["proxies"].append(proxy)
            break
    else:
        logger.warning(f"不支持的节点协议: {node_url}")
        return False

    if not config["proxies"]:
        logger.error(f"未为 {node_url} 配置代理。")
        return False

    try:
        # 使用临时配置文件名以避免并发测试之间的冲突
        temp_config_file = Path(f"config_{port}.yaml")
        with temp_config_file.open('w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        logger.info(f"已为 {node_url} 在 {temp_config_file} 生成Clash.Meta配置。")
        return temp_config_file
    except (OSError, yaml.YAMLError) as e:
        logger.error(f"写入 {node_url} 的Clash.Meta配置时出错: {e}")
        return False

@asynccontextmanager
async def mihomo_process(config_file, port):
    """用于运行和清理Mihomo进程的上下文管理器。"""
    process = None
    try:
        logger.info(f"正在启动 {MIHOMO_BIN_NAME}，配置文件 {config_file}，端口 {port}...")
        process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", str(config_file)],
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
            bufsize=1
        )
        logger.info(f"{MIHOMO_BIN_NAME} 进程已启动 (PID: {process.pid})。给它一些时间进行初始化...")
        # 优化: 增加睡眠时间，确保Mihomo有足够时间初始化。
        await asyncio.sleep(5) # 从2秒增加到5秒
        yield process
    finally:
        if process and process.poll() is None:
            logger.info(f"正在终止 {MIHOMO_BIN_NAME} 进程 (PID: {process.pid})...")
            process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
                logger.info(f"{MIHOMO_BIN_NAME} 进程已终止 (PID: {process.pid})")
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"已强制杀死 {MIHOMO_BIN_NAME} 进程 (PID: {process.pid})")
        else:
            logger.info(f"{MIHOMO_BIN_NAME} 进程未运行或已终止。")
        
        if config_file.exists():
            config_file.unlink()
            logger.info(f"已清理配置文件 {config_file}。")

async def test_node_connectivity(node_url, current_port):
    """使用Clash.Meta测试单个节点的连接性。"""
    logger.info(f"\n--- 正在测试节点: {node_url}，端口 {current_port} ---")
    
    temp_config_file = create_clash_config(node_url, current_port)
    if not temp_config_file:
        logger.warning(f"由于解析错误或不支持的协议，跳过节点: {node_url}。")
        return None

    try:
        async with mihomo_process(temp_config_file, current_port):
            curl_command = [
                "curl",
                "--socks5-hostname", f"127.0.0.1:{current_port}",
                TEST_URL,
                "--max-time", "15",
                "--silent", "--output", "/dev/null",
                "--fail"
            ]
            logger.info(f"正在运行curl命令: {' '.join(curl_command)}")
            result = await asyncio.to_thread(subprocess.run, curl_command, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"节点 {node_url} 已连接。")
                return node_url
            logger.warning(f"节点 {node_url} 连接失败 (curl退出码: {result.returncode})。")
            logger.debug(f"Curl stdout:\n{result.stdout}")
            logger.debug(f"Curl stderr:\n{result.stderr}")
            return None
    except FileNotFoundError:
        logger.error(f"错误: 找不到 {MIHOMO_BIN_NAME}。请确保它在当前目录且可执行。")
        return None
    except subprocess.SubprocessError as e:
        logger.error(f"测试 {node_url} 时发生子进程错误: {e}")
        return None
    except Exception as e:
        logger.error(f"测试 {node_url} 时发生意外错误: {e}")
        return None

async def main():
    """主函数，用于处理代理节点。"""
    logger.info("开始代理节点处理脚本。")
    setup_mihomo()
    OUTPUT_DIR.mkdir(exist_ok=True)
    logger.info(f"确保输出目录 '{OUTPUT_DIR}' 存在。")

    all_nodes = download_and_parse_nodes(NODE_LIST_URL)
    
    # 使用信号量限制并发任务
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)

    # 创建一个队列来管理并发测试的可用端口
    port_queue = asyncio.Queue()
    for i in range(CONCURRENT_TESTS):
        await port_queue.put(CLASH_BASE_PORT + i)

    async def bounded_test_with_node_return(node_url_to_test):
        async with semaphore:
            # 从端口池中获取一个端口
            current_port = await port_queue.get()
            try:
                result_node_url = await test_node_connectivity(node_url_to_test, current_port)
                return result_node_url
            finally:
                # 将端口释放回池中
                await port_queue.put(current_port) # 确保端口被返回

    tasks = [bounded_test_with_node_return(node) for node in all_nodes]
    
    working_nodes = []
    # 按照任务完成的顺序处理
    for i, future in enumerate(asyncio.as_completed(tasks)):
        completed_node_url = await future
        if completed_node_url:
            working_nodes.append(completed_node_url)
        logger.info(f"已处理 {i+1}/{len(all_nodes)} 个节点。")

    logger.info(f"\n--- 脚本执行完成 ---")
    logger.info(f"总共处理的节点数: {len(all_nodes)}")
    logger.info(f"找到的可用节点数: {len(working_nodes)}")

    with OUTPUT_FILE.open('w', encoding='utf-8') as f:
        for node in working_nodes:
            f.write(node + "\n")
    logger.info(f"可用节点已保存到 {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
