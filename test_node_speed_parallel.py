
import yaml
import speedtest
import asyncio
import socks
import socket
import http.client
import logging
from concurrent.futures import ThreadPoolExecutor
from operator import itemgetter
import time
import requests
import base64
import urllib.parse
import json

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 远程订阅地址
SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
    # 可添加其他订阅地址，例如从 X 帖子获取的链接
    # "http://43.203.203.210:8081",
    # "http://18.141.173.68:8081",
]

def parse_proxy_url(url):
    """解析多种协议的节点为 Clash 格式"""
    try:
        if url.startswith("hysteria2://"):
            parsed = urllib.parse.urlparse(url)
            auth = parsed.username or ""
            host, port = parsed.hostname, parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            return {
                "name": parsed.fragment or f"hysteria2_{host}",
                "type": "hysteria2",
                "server": host,
                "port": port,
                "auth": auth,
                "sni": query.get("sni", [host])[0],
                "skip-cert-verify": query.get("insecure", ["true"])[0].lower() == "true",
                "up-speed": int(query.get("upmbps", ["100"])[0]),
                "down-speed": int(query.get("downmbps", ["100"])[0]),
            }
        elif url.startswith("vmess://"):
            decoded = json.loads(base64.b64decode(url[8:]).decode())
            return {
                "name": decoded.get("ps", f"vmess_{decoded['add']}"),
                "type": "vmess",
                "server": decoded["add"],
                "port": int(decoded["port"]),
                "uuid": decoded["id"],
                "alterId": int(decoded.get("aid", 0)),
                "cipher": decoded.get("scy", "auto"),
                "network": decoded.get("net", "tcp"),
                "tls": decoded.get("tls", "") == "tls",
                "ws-opts": {"path": decoded.get("path", "/"), "headers": {"Host": decoded.get("host", "")}} if decoded.get("net") == "ws" else {},
            }
        elif url.startswith("trojan://"):
            parsed = urllib.parse.urlparse(url)
            password = parsed.username or ""
            host, port = parsed.hostname, parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            return {
                "name": parsed.fragment or f"trojan_{host}",
                "type": "trojan",
                "server": host,
                "port": port,
                "password": password,
                "sni": query.get("sni", [host])[0],
                "skip-cert-verify": query.get("allowInsecure", ["true"])[0].lower() == "true",
            }
        elif url.startswith("ss://"):
            decoded = base64.b64decode(url[5:].split("#")[0]).decode().split("@")
            cipher_password, server_port = decoded[0], decoded[1]
            cipher, password = cipher_password.split(":")
            server, port = server_port.split(":")
            name = urllib.parse.unquote(url.split("#")[-1]) if "#" in url else f"ss_{server}"
            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": cipher,
                "password": password,
            }
        elif url.startswith("ssr://"):
            decoded = base64.b64decode(url[6:]).decode().split(":")
            server, port, protocol, cipher, obfs, password = decoded[:6]
            password = base64.b64decode(password).decode()
            params = urllib.parse.parse_qs(decoded[-1].lstrip("/?"))
            name = params.get("remarks", [f"ssr_{server}"])[0]
            return {
                "name": base64.b64decode(name).decode() if name else f"ssr_{server}",
                "type": "ssr",
                "server": server,
                "port": int(port),
                "protocol": protocol,
                "cipher": cipher,
                "obfs": obfs,
                "password": password,
                "obfs-param": params.get("obfsparam", [""])[0],
                "protocol-param": params.get("protoparam", [""])[0],
            }
        elif url.startswith("vless://"):
            parsed = urllib.parse.urlparse(url)
            uuid = parsed.username or ""
            host, port = parsed.hostname, parsed.port or 443
            query = urllib.parse.parse_qs(parsed.query)
            return {
                "name": parsed.fragment or f"vless_{host}",
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": uuid,
                "tls": query.get("security", ["tls"])[0] == "tls",
                "skip-cert-verify": query.get("allowInsecure", ["true"])[0].lower() == "true",
                "network": query.get("type", ["tcp"])[0],
                "ws-opts": {"path": query.get("path", ["/"])[0], "headers": {"Host": query.get("host", [""])[0]}} if query.get("type", [""])[0] == "ws" else {},
            }
        else:
            logger.warning(f"不支持的协议: {url[:10]}...")
            return None
    except Exception as e:
        logger.error(f"解析节点 {url[:10]}... 失败: {str(e)}")
        return None

def fetch_remote_nodes():
    """从远程订阅地址获取节点"""
    all_proxies = []
    for url in SUBSCRIPTION_URLS:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            if url.endswith(".yml"):
                data = yaml.safe_load(response.text)
                proxies = data.get("proxies", [])
                all_proxies.extend(proxies)
            else:
                nodes = response.text.strip().split("\n")
                for node in nodes:
                    proxy = parse_proxy_url(node)
                    if proxy:
                        all_proxies.append(proxy)
            logger.info(f"从 {url} 获取 {len(proxies)} 个节点")
        except Exception as e:
            logger.error(f"获取远程节点 {url} 失败: {str(e)}")
    return all_proxies

def test_node_connectivity(proxy):
    """测试节点连接性和延迟"""
    try:
        proxy_type = proxy.get('type', '').lower()
        if proxy_type not in ['ss', 'vmess', 'trojan', 'ssr', 'vless', 'hysteria2']:
            logger.warning(f"节点 {proxy['name']} 的类型 {proxy_type} 不支持，跳过")
            return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'connectivity': False, 'config': proxy}

        # 设置代理
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_type in ['ss', 'ssr', 'vmess', 'vless', 'trojan'] else socks.HTTP,
            proxy['server'],
            proxy['port'],
            username=proxy.get('username', '') or proxy.get('uuid', '') or proxy.get('password', ''),
            password=proxy.get('password', '') or proxy.get('auth', '')
        )
        socket.socket = socks.socksocket

        # 测试延迟和连接性（外部来源：api.github.com）
        start_time = time.time()
        try:
            conn = http.client.HTTPSConnection("api.github.com", timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            if response.status == 200:
                latency = (time.time() - start_time) * 1000  # 转换为毫秒
                logger.info(f"节点 {proxy['name']} 外部连接成功，延迟: {latency:.2f} ms")
                return {'name': proxy['name'], 'speed': None, 'latency': latency, 'connectivity': True, 'config': proxy}
            else:
                logger.error(f"节点 {proxy['name']} 外部连接失败，状态码: {response.status}")
                return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'connectivity': False, 'config': proxy}
        except Exception as e:
            logger.error(f"节点 {proxy['name']} 延迟/连接性测试失败: {str(e)}")
            return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'connectivity': False, 'config': proxy}
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"测试节点 {proxy['name']} 失败: {str(e)}")
        return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'connectivity': False, 'config': proxy}

def test_node_speed_sync(proxy):
    """同步测试节点下载速度（仅对连接性测试通过的节点）"""
    try:
        s = speedtest.Speedtest()
        s.get_best_server()
        download_speed = s.download() / 1000000  # 转换为 Mbps
        logger.info(f"节点 {proxy['name']} 下载速度: {download_speed:.2f} Mbps")
        return {'name': proxy['name'], 'speed': download_speed, 'latency': proxy['latency'], 'connectivity': True, 'config': proxy}
    except Exception as e:
        logger.error(f"节点 {proxy['name']} 速度测试失败: {str(e)}")
        return {'name': proxy['name'], 'speed': 0, 'latency': proxy['latency'], 'connectivity': True, 'config': proxy}

async def test_node_speed(proxy, executor):
    """异步包装速度测试函数"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, test_node_speed_sync, proxy)

async def main():
    # 读取本地 Clash 配置文件
    local_proxies = []
    try:
        with open('clash_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        local_proxies = config.get('proxies', [])
        logger.info(f"从本地 clash_config.yaml 获取 {len(local_proxies)} 个节点")
    except FileNotFoundError:
        logger.warning("找不到 clash_config.yaml 文件，仅使用远程节点")
    except yaml.YAMLError as e:
        logger.error(f"解析本地 YAML 文件失败: {str(e)}")

    # 获取远程节点
    remote_proxies = fetch_remote_nodes()

    # 合并节点（去重）
    proxies = local_proxies + remote_proxies
    unique_proxies = []
    seen = set()
    for proxy in proxies:
        key = (proxy['server'], proxy['port'], proxy.get('password', ''), proxy.get('uuid', ''))
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)

    if not unique_proxies:
        logger.error("没有可用的节点")
        return

    # 第一阶段：并行测试连接性和延迟
    max_workers = min(len(unique_proxies), 5)
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        tasks = [test_node_connectivity(proxy) for proxy in unique_proxies]
        connectivity_results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        executor.shutdown(wait=True)

    # 过滤连接性测试通过的节点
    valid_connectivity = [r for r in connectivity_results if isinstance(r, dict) and r['connectivity']]
    if not valid_connectivity:
        logger.error("没有节点通过连接性测试")
        return

    # 第二阶段：对连接性通过的节点进行速度测试
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        tasks = [test_node_speed(proxy, executor) for proxy in valid_connectivity]
        speed_results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        executor.shutdown(wait=True)

    # 过滤速度测试成功的节点并排序
    valid_results = [r for r in speed_results if isinstance(r, dict) and r['speed'] > 0]
    sorted_results = sorted(valid_results, key=lambda x: (x['speed'], -x['latency']), reverse=True)

    # 更新节点名称，附加速度和延迟
    for result in sorted_results:
        result['config']['name'] = f"{result['name']} - {result['speed']:.2f} Mbps - {result['latency']:.2f} ms"

    # 准备新的配置文件
    new_config = config.copy() if 'config' in locals() else {'proxies': []}
    new_config['proxies'] = [result['config'] for result in sorted_results]

    # 保存结果到新的 YAML 文件
    try:
        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yaml.safe_dump(new_config, f, allow_unicode=True, sort_keys=False)
        logger.info("测试结果已保存到 clash.yaml")
        
        # 打印测试结果
        logger.info("\n测试结果（按速度从快到慢，延迟从小到大）：")
        for result in sorted_results:
            logger.info(f"节点: {result['config']['name']}, 速度: {result['speed']:.2f} Mbps, 延迟: {result['latency']:.2f} ms")
    except Exception as e:
        logger.error(f"保存结果失败: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
