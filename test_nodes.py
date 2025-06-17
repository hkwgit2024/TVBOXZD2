import aiohttp
import asyncio
import yaml
import os
import subprocess
import time
import argparse
import base64
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote
import re
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def fetch_proxies(url: str) -> List[Dict]:
    """从远程 URL 下载并解析代理节点"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=30) as response:
                if response.status != 200:
                    logger.error(f"无法从 {url} 获取代理节点: HTTP {response.status}")
                    return []
                content = await response.text()
            proxies = []
            for line in content.splitlines():
                proxy = parse_proxy_line(line.strip())
                if proxy:
                    proxies.append(proxy)
            logger.info(f"从 {url} 加载了 {len(proxies)} 个代理节点")
            return proxies
        except Exception as e:
            logger.error(f"获取代理节点失败: {e}")
            return []

def parse_proxy_line(line: str) -> Optional[Dict]:
    """解析单行代理 URI，支持多种协议"""
    try:
        # 分离 URI 和节点名称
        parts = line.split('#', 1)
        uri = parts[0]
        name = unquote(parts[1]) if len(parts) > 1 else f"未知节点_{time.time()}"  # 解码节点名称
        url_parts = urlparse(uri)
        scheme = url_parts.scheme.lower()
        proxy = {'name': name}  # 使用解码后的名称

        if scheme == 'ss':
            # Shadowsocks: ss://cipher:password@server:port 或 ss://base64@server:port
            try:
                auth_data = url_parts.netloc.split('@')
                if len(auth_data) != 2:
                    logger.warning(f"解析 SS 节点失败，格式错误: {uri}")
                    return None
                server_port = auth_data[1].split(':')
                if len(server_port) != 2:
                    logger.warning(f"SS 节点无效服务器或端口: {uri}")
                    return None
                proxy['type'] = 'ss'
                proxy['server'] = server_port[0]
                proxy['port'] = int(server_port[1])
                # 处理 Base64 编码的 cipher:password
                auth = auth_data[0]
                if auth.startswith('YWVz') or auth.startswith('Y2hhY2hh'):  # Base64 前缀
                    decoded_auth = base64.b64decode(auth + '==' * (-len(auth) % 4)).decode('utf-8')
                    if ':' not in decoded_auth:
                        logger.warning(f"SS 节点缺少加密方法或密码: {uri}")
                        return None
                    proxy['cipher'], proxy['password'] = decoded_auth.split(':')
                else:
                    if ':' not in auth:
                        logger.warning(f"SS 节点缺少加密方法或密码: {uri}")
                        return None
                    proxy['cipher'], proxy['password'] = auth.split(':')
                return proxy
            except Exception as e:
                logger.warning(f"解析 SS 节点失败: {uri}, 错误: {e}")
                return None

        elif scheme == 'vmess':
            # VMess: vmess://base64 或 vmess://uuid@server:port?params
            try:
                if url_parts.netloc:  # URI 格式
                    auth_data = url_parts.netloc.split('@')
                    if len(auth_data) != 2:
                        logger.warning(f"解析 VMess 节点失败，格式错误: {uri}")
                        return None
                    proxy['type'] = 'vmess'
                    proxy['uuid'] = auth_data[0]
                    server_port = auth_data[1].split(':')
                    proxy['server'] = server_port[0]
                    proxy['port'] = int(server_port[1])
                    params = parse_qs(url_parts.query)
                else:  # Base64 编码的 JSON
                    decoded = base64.b64decode(uri[8:] + '==' * (-len(uri[8:]) % 4)).decode('utf-8')
                    config = json.loads(decoded)
                    proxy['type'] = 'vmess'
                    proxy['server'] = config['add']
                    proxy['port'] = int(config['port'])
                    proxy['uuid'] = config['id']
                    proxy['alterId'] = int(config.get('aid', '0'))
                    proxy['network'] = config.get('net', 'tcp')
                    proxy['tls'] = config.get('tls', '') == 'tls'
                    proxy['sni'] = config.get('host', '')
                    proxy['path'] = config.get('path', '')
                    proxy['name'] = unquote(config.get('ps', name))  # 解码 ps 字段
                return proxy
            except Exception as e:
                logger.warning(f"解析 VMess 节点失败: {uri}, 错误: {e}")
                return None

        elif scheme == 'vless':
            # VLESS: vless://uuid@server:port?params
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                logger.warning(f"解析 VLESS 节点失败，格式错误: {uri}")
                return None
            proxy['type'] = 'vless'
            proxy['uuid'] = auth_data[0]
            server_port = auth_data[1].split(':')
            proxy['server'] = server_port[0]
            proxy['port'] = int(server_port[1])
            params = parse_qs(url_parts.query)
            proxy['flow'] = params.get('flow', [''])[0]
            proxy['encryption'] = params.get('encryption', ['none'])[0]
            proxy['security'] = params.get('security', [''])[0]
            proxy['sni'] = params.get('sni', [''])[0]
            return proxy

        elif scheme == 'trojan':
            # Trojan: trojan://password@server:port?params
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                logger.warning(f"解析 Trojan 节点失败，格式错误: {uri}")
                return None
            proxy['type'] = 'trojan'
            proxy['password'] = auth_data[0]
            server_port = auth_data[1]
            ipv6_match = re.match(r'\[(.*?)\]:(\d+)', server_port)
            if ipv6_match:
                proxy['server'] = ipv6_match.group(1)
                proxy['port'] = int(ipv6_match.group(2))
            else:
                try:
                    proxy['server'], proxy['port'] = server_port.split(':')
                    proxy['port'] = int(proxy['port'])
                except ValueError:
                    logger.warning(f"Trojan 节点无效服务器或端口: {uri}")
                    return None
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            proxy['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'
            proxy['network'] = params.get('type', ['tcp'])[0]
            proxy['path'] = params.get('path', [''])[0]
            proxy['host'] = params.get('host', [''])[0]
            return proxy

        elif scheme == 'hysteria2':
            # Hysteria2: hysteria2://password@server:port?params
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                logger.warning(f"解析 Hysteria2 节点失败，格式错误: {uri}")
                return None
            proxy['type'] = 'hysteria2'
            proxy['password'] = auth_data[0]
            server_port = auth_data[1].split(':')
            if len(server_port) != 2:
                logger.warning(f"Hysteria2 节点无效服务器或端口: {uri}")
                return None
            proxy['server'] = server_port[0]
            proxy['port'] = int(server_port[1])
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            proxy['skip-cert-verify'] = params.get('insecure', ['0'])[0] == '1'
            proxy['mport'] = params.get('mport', [''])[0]
            proxy['obfs'] = params.get('obfs', ['none'])[0]
            proxy['peer'] = params.get('peer', [''])[0]
            return proxy

        elif scheme == 'ssr':
            # ShadowsocksR: ssr://base64
            try:
                decoded = base64.b64decode(uri[6:] + '==' * (-len(uri[6:]) % 4)).decode('utf-8')
                parts = decoded.split(':')
                if len(parts) < 6:
                    logger.warning(f"解析 SSR 节点失败，格式错误: {uri}")
                    return None
                proxy['type'] = 'ssr'
                proxy['server'] = parts[0]
                proxy['port'] = int(parts[1])
                proxy['protocol'] = parts[2]
                proxy['cipher'] = parts[3]
                proxy['obfs'] = parts[4]
                proxy['password'] = base64.b64decode(parts[5].split('/')[0] + '==' * (-len(parts[5].split('/')[0]) % 4)).decode('utf-8')
                params = parse_qs(decoded.split('?')[1]) if '?' in decoded else {}
                proxy['obfs-param'] = base64.b64decode(params.get('obfsparam', [''])[0] + '==' * (-len(params.get('obfsparam', [''])[0]) % 4)).decode('utf-8') if params.get('obfsparam') else ''
                proxy['protocol-param'] = base64.b64decode(params.get('protoparam', [''])[0] + '==' * (-len(params.get('protoparam', [''])[0]) % 4)).decode('utf-8') if params.get('protoparam') else ''
                return proxy
            except Exception as e:
                logger.warning(f"解析 SSR 节点失败: {uri}, 错误: {e}")
                return None

        else:
            logger.warning(f"不支持的协议: {scheme}")
            return None
    except Exception as e:
        logger.warning(f"解析代理行失败 {line}: {e}")
        return None

async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    """测试单个代理节点"""
    result = {'proxy': proxy, 'status': '不可用', 'latency': 0, 'error': ''}
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'error',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy['name']]}],
        'rules': ['MATCH,auto']
    }
    config_path = f'config_{clash_port}.yaml'
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
        proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await asyncio.sleep(2)
        try:
            start_time = time.time()
            async with session.get(
                'http://www.google.com',
                proxy=f'http://127.0.0.1:{clash_port}',
                timeout=5
            ) as response:
                if response.status == 200:
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000
        except Exception as e:
            result['error'] = str(e)
            if proxy['type'] == 'hysteria2':
                stderr = proc.stderr.read().decode()
                if stderr:
                    result['error'] += f" | Mihomo 日志: {stderr}"
        finally:
            proc.terminate()
            await asyncio.sleep(0.2)
            if os.path.exists(config_path):
                os.remove(config_path)
    except Exception as e:
        result['error'] = f"配置生成失败: {str(e)}"
    logger.info(f"{proxy['name']}: {result['status']}, 延迟: {result['latency']:.2f}ms")
    return result

async def main():
    """主函数，运行代理测试"""
    parser = argparse.ArgumentParser(description='测试代理节点')
    parser.add_argument('--chunk', type=int, default=0, help='并行测试的分片索引')
    parser.add_argument('--total-chunks', type=int, default=1, help='总分片数')
    args = parser.parse_args()

    proxy_url = 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt'
    clash_bin = './tools/clash'
    batch_size = 100  # 每批测试 100 个节点
    base_port = 7890

    # 确保 data 目录存在
    os.makedirs('data', exist_ok=True)

    async with aiohttp.ClientSession() as session:
        proxies = await fetch_proxies(proxy_url)
        if not proxies:
            logger.error("没有可测试的代理节点")
            return

        # 分片处理
        chunk_size = len(proxies) // args.total_chunks
        start = args.chunk * chunk_size
        end = start + chunk_size if args.chunk < args.total_chunks - 1 else len(proxies)
        proxies = proxies[start:end]
        logger.info(f"测试分片 {args.chunk}/{args.total_chunks}: {len(proxies)} 个节点")

        results = []
        for i in range(0, len(proxies), batch_size):
            batch = proxies[i:i + batch_size]
            batch_results = await asyncio.gather(
                *(test_proxy(proxy, session, clash_bin, base_port + j) for j, proxy in enumerate(batch))
            )
            results.extend(batch_results)

        # 保存结果
        output_prefix = f"_chunk_{args.chunk}" if args.total_chunks > 1 else ""
        with open(f'data/521{output_prefix}.yaml', 'w', encoding='utf-8') as f:
            yaml.dump([r['proxy'] for r in results if r['status'] == '可用'], f, allow_unicode=True)
        with open(f'data/invalid_nodes{output_prefix}.yaml', 'w', encoding='utf-8') as f:
            yaml.dump([r['proxy'] for r in results if r['status'] == '不可用'], f, allow_unicode=True)
        logger.info(f"结果已保存至 data/521{output_prefix}.yaml 和 data/invalid_nodes{output_prefix}.yaml")

if __name__ == '__main__':
    asyncio.run(main())
