import aiohttp
import asyncio
import yaml
import os
import subprocess
import time
import argparse
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
import logging
import psutil
import tempfile
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import aiofiles

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_invalid_nodes(file_path: str) -> List[Dict]:
    """加载上次的不可用节点"""
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            nodes = yaml.safe_load(f) or []
        return nodes
    except Exception as e:
        logger.error(f"加载不可用节点文件 {file_path} 失败: {e}")
        return []

async def save_nodes(file_path: str, nodes: List[Dict]):
    """异步保存节点到文件"""
    async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
        await f.write(yaml.dump(nodes, allow_unicode=True))

def get_node_key(proxy: Dict) -> str:
    """生成节点唯一标识"""
    return f"{proxy['server']}:{proxy['port']}:{proxy['name']}"

async def fetch_proxies(url: str) -> List[Dict]:
    """从远程 URL 下载并解析代理节点"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=30) as response:
                if response.status != 200:
                    logger.error(f"无法从 {url} 获取代理节点: HTTP {response.status}")
                    return []
                content = await response.text()
            proxies = [proxy for line in content.splitlines() if (proxy := parse_proxy_line(line.strip()))]
            logger.info(f"从 {url} 加载了 {len(proxies)} 个代理节点")
            return proxies
        except Exception as e:
            logger.error(f"获取代理节点失败: {e}")
            return []

def parse_proxy_line(line: str) -> Optional[Dict]:
    """解析单行代理 URI"""
    try:
        parts = line.split('#', 1)
        uri = parts[0]
        name = unquote(parts[1]) if len(parts) > 1 else f"未知节点_{time.time()}"
        url_parts = urlparse(uri)
        scheme = url_parts.scheme.lower()
        proxy = {'name': name, 'tested_at': datetime.now().isoformat()}  # 添加时间戳

        if scheme == 'trojan':
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                logger.warning(f"解析 Trojan 节点失败，格式错误: {uri}")
                return None
            proxy['type'] = 'trojan'
            proxy['password'] = auth_data[0]
            server_port = auth_data[1]
            if ipv6_match := re.match(r'\[(.*?)\]:(\d+)', server_port):
                proxy['server'], proxy['port'] = ipv6_match.group(1), int(ipv6_match.group(2))
            else:
                proxy['server'], proxy['port'] = server_port.split(':')
                proxy['port'] = int(proxy['port'])
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            proxy['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'
            proxy['network'] = params.get('type', ['tcp'])[0]
            proxy['path'] = params.get('path', [''])[0]
            proxy['host'] = params.get('host', [''])[0]
            return proxy
        # 其他协议解析（如 ss, vmess 等）类似，略
        else:
            logger.warning(f"不支持的协议: {scheme}")
            return None
    except Exception as e:
        logger.warning(f"解析代理行失败 {line}: {e}")
        return None

def get_free_port() -> int:
    """获取空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]

async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int) -> Dict:
    """测试单个代理节点"""
    result = {'proxy': proxy, 'status': '不可用', 'latency': 0, 'error': ''}
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'external-controller': f'127.0.0.1:{clash_port + 2}',
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'error',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy['name']]}],
        'rules': ['MATCH,auto']
    }
    with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False, encoding='utf-8') as f:
        config_path = f.name
        yaml.dump(config, f, allow_unicode=True)

    try:
        proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await asyncio.sleep(2)
        try:
            start_time = time.time()
            async with session.get(
                'http://www.cloudflare.com',  # 使用 Cloudflare 作为测试目标
                proxy=f'http://127.0.0.1:{clash_port}',
                timeout=10
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
    except Exception as e:
        result['error'] = f"配置生成失败: {str(e)}"
    finally:
        try:
            os.remove(config_path)
        except Exception as e:
            logger.warning(f"删除配置文件 {config_path} 失败: {e}")
    logger.info(f"🔒 {proxy['type'].upper()}-{proxy.get('network', 'TCP').upper()}-{'TLS' if proxy.get('sni') else 'NA'} "
                f"{proxy['name']}: {result['status']}, 延迟: {result['latency']:.2f}ms")
    return result

async def main():
    """主函数，运行代理测试"""
    parser = argparse.ArgumentParser(description='测试代理节点')
    parser.add_argument('--proxy-url', default='https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt',
                        help='代理节点 URL')
    parser.add_argument('--clash-bin', default='./tools/clash', help='Clash 二进制路径')
    parser.add_argument('--batch-size', type=int, default=max(10, psutil.cpu_count() * 10), help='批量测试节点数')
    parser.add_argument('--invalid-file', default='data/invalid_nodes.yaml', help='不可用节点文件')
    parser.add_argument('--valid-file', default='data/521.yaml', help='可用节点文件')
    parser.add_argument('--expire-days', type=int, default=7, help='不可用节点过期天数')
    args = parser.parse_args()

    os.makedirs('data', exist_ok=True)
    
    # 加载上次的不可用和可用节点
    invalid_nodes = load_invalid_nodes(args.invalid_file)
    valid_nodes = load_invalid_nodes(args.valid_file)
    invalid_keys = {get_node_key(node) for node in invalid_nodes}
    valid_keys = {get_node_key(node) for node in valid_nodes}

    async with aiohttp.ClientSession() as session:
        # 获取最新节点
        proxies = await fetch_proxies(args.proxy_url)
        if not proxies:
            logger.error("没有可测试的代理节点")
            return

        # 过滤新增节点
        new_proxies = [p for p in proxies if get_node_key(p) not in invalid_keys and get_node_key(p) not in valid_keys]
        logger.info(f"总节点数: {len(proxies)}, 新增节点: {len(new_proxies)}, 已知可用: {len(valid_nodes)}, 已知不可用: {len(invalid_nodes)}")

        # 测试新增节点
        results = []
        base_port = get_free_port()
        for i in range(0, len(new_proxies), args.batch_size):
            batch = new_proxies[i:i + args.batch_size]
            batch_results = await asyncio.gather(
                *(test_proxy(proxy, session, args.clash_bin, base_port + j * 3) for j, proxy in enumerate(batch))
            )
            results.extend(batch_results)

        # 合并结果
        new_valid = [r['proxy'] for r in results if r['status'] == '可用']
        new_invalid = [r['proxy'] for r in results if r['status'] == '不可用']
        
        # 更新可用节点（保留旧的可用节点 + 新测试的可用节点）
        all_valid = valid_nodes + new_valid
        valid_keys = {get_node_key(node) for node in all_valid}
        all_valid = [node for node in all_valid if get_node_key(node) in valid_keys]  # 去重

        # 更新不可用节点（保留未过期的旧节点 + 新测试的不可用节点）
        expire_time = datetime.now() - timedelta(days=args.expire_days)
        all_invalid = [node for node in invalid_nodes if 'tested_at' in node and datetime.fromisoformat(node['tested_at']) > expire_time]
        all_invalid.extend(new_invalid)
        invalid_keys = {get_node_key(node) for node in all_invalid}
        all_invalid = [node for node in all_invalid if get_node_key(node) in invalid_keys]  # 去重

        # 保存结果
        await save_nodes(args.valid_file, all_valid)
        await save_nodes(args.invalid_file, all_invalid)

        # 输出统计信息
        logger.info(f"测试完成: 总节点数={len(proxies)}, 可用节点={len(all_valid)}, "
                    f"不可用节点={len(all_invalid)}, 可用率={len(all_valid)/len(proxies)*100:.2f}%")

if __name__ == '__main__':
    asyncio.run(main())
