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
import re # Added import for re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_invalid_nodes(file_path: str) -> List[Dict]:
    """
    加载上次的不可用节点。
    过滤掉任何非字典类型的条目，以确保数据的有效性。
    """
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            nodes = yaml.safe_load(f) or []
        # 过滤掉任何可能已被加载的非字典条目，这是一种防御性检查
        filtered_nodes = [node for node in nodes if isinstance(node, dict)]
        return filtered_nodes
    except Exception as e:
        logger.error(f"加载不可用节点文件 {file_path} 失败: {e}")
        return []

async def save_nodes(file_path: str, nodes: List[Dict]):
    """异步保存节点到文件"""
    async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
        await f.write(yaml.dump(nodes, allow_unicode=True))

def get_node_key(proxy: Dict) -> str:
    """
    生成节点唯一标识。
    增加健壮性检查，确保 proxy 是字典且包含所有必要键。
    """
    if not isinstance(proxy, dict):
        logger.warning(f"get_node_key 收到非字典类型: {proxy}. 跳过生成键。")
        return "" # 如果不是字典，则返回空字符串，表示无法生成有效键
    required_keys = ['server', 'port', 'name']
    if not all(key in proxy for key in required_keys):
        logger.warning(f"代理缺少生成节点键所需的信息: {proxy}. 跳过生成键。")
        return "" # 如果缺少必要键，也返回空字符串
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
                # 立即过滤掉 parse_proxy_line 返回的 None 结果
                proxies = [proxy for line in content.splitlines() if (proxy := parse_proxy_line(line.strip())) is not None]
                logger.info(f"从 {url} 加载了 {len(proxies)} 个代理节点")
                return proxies
        except Exception as e:
            logger.error(f"获取代理节点失败: {e}")
            return []

def parse_proxy_line(line: str) -> Optional[Dict]:
    """解析单行代理 URI，支持 Trojan, SS, Vmess, Hysteria2"""
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
                host, port_str = server_port.split(':')
                proxy['server'] = host
                proxy['port'] = int(port_str)
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            # Trojan 使用 allowInsecure 参数
            proxy['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'
            proxy['network'] = params.get('type', ['tcp'])[0]
            proxy['path'] = params.get('path', [''])[0]
            proxy['host'] = params.get('host', [''])[0]
            return proxy
        elif scheme == 'ss':
            try:
                # Shadowsocks URI 格式通常为 base64(method:password@server:port)
                # 或者直接是 ss://method:password@server:port#name
                # 这里假设是 base64(method:password@server:port)
                decoded_uri = base64.b64decode(url_parts.netloc).decode('utf-8')
                parts = decoded_uri.split('@')
                if len(parts) != 2: raise ValueError("无效的 Shadowsocks URI 格式")
                method_passwd = parts[0].split(':', 1)
                server_port = parts[1].split(':', 1)

                proxy['type'] = 'ss'
                proxy['cipher'] = method_passwd[0]
                proxy['password'] = method_passwd[1]
                proxy['server'] = server_port[0]
                proxy['port'] = int(server_port[1])
                return proxy
            except Exception as ss_e:
                logger.warning(f"解析 Shadowsocks 节点失败 {uri}: {ss_e}")
                return None
        elif scheme == 'vmess':
            # VMESS URI 通常是 base64 编码的 JSON 字符串
            try:
                decoded_vmess = base64.b64decode(url_parts.netloc).decode('utf-8')
                vmess_data = json.loads(decoded_vmess)
                proxy['type'] = 'vmess'
                proxy['server'] = vmess_data.get('add')
                proxy['port'] = int(vmess_data.get('port'))
                proxy['uuid'] = vmess_data.get('id')
                proxy['alterId'] = vmess_data.get('aid', 0)
                proxy['cipher'] = vmess_data.get('scy', 'auto') # security
                proxy['network'] = vmess_data.get('net', 'tcp')
                proxy['tls'] = vmess_data.get('tls', '') == 'tls'
                proxy['ws-path'] = vmess_data.get('path', '')
                proxy['ws-headers'] = {'Host': vmess_data.get('host', '')} if vmess_data.get('host') else {}
                return proxy
            except Exception as vmess_e:
                logger.warning(f"解析 Vmess 节点失败 {uri}: {vmess_e}")
                return None
        elif scheme == 'hy2' or scheme == 'hysteria2':
            # Hysteria2 URI 格式: hy2://password@server:port?sni=example.com&obfs=none&obfs-password=
            try:
                password_server_port = url_parts.netloc
                parts = password_server_port.split('@', 1)
                password = parts[0]
                server_port_str = parts[1] if len(parts) > 1 else ''

                if not server_port_str:
                    logger.warning(f"解析 Hysteria2 节点失败，缺少服务器和端口信息: {uri}")
                    return None

                if ipv6_match := re.match(r'\[(.*?)\]:(\d+)', server_port_str):
                    server, port = ipv6_match.group(1), int(ipv6_match.group(2))
                else:
                    server, port_str = server_port_str.split(':')
                    port = int(port_str)

                params = parse_qs(url_parts.query)

                proxy['type'] = 'hysteria2'
                proxy['password'] = password
                proxy['server'] = server
                proxy['port'] = port
                proxy['obfs'] = params.get('obfs', ['none'])[0]
                proxy['obfs-password'] = params.get('obfs-password', [''])[0]
                proxy['sni'] = params.get('sni', [''])[0]
                # Hysteria2 使用 'insecure' 参数而不是 'allowInsecure'
                proxy['skip-cert-verify'] = params.get('insecure', ['0'])[0] == '1' 
                return proxy
            except Exception as hy2_e:
                logger.warning(f"解析 Hysteria2 节点失败 {uri}: {hy2_e}")
                return None
        else:
            logger.warning(f"不支持的协议: {scheme}. URI: {uri}")
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
    """
    测试单个代理节点。
    创建 Clash 配置文件并启动 Clash 进程，然后通过 Clash 测试代理。
    """
    result = {'proxy': proxy, 'status': '不可用', 'latency': 0, 'error': ''}
    
    # 确保代理字典包含所有必要的键来构建 Clash 配置
    required_clash_keys = ['name', 'type', 'server', 'port']
    if not all(key in proxy for key in required_clash_keys):
        result['error'] = "代理配置缺少必要信息 (name, type, server, port)。"
        logger.error(f"代理配置缺少必要信息: {proxy}")
        return result

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
    
    config_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            config_path = f.name
            yaml.dump(config, f, allow_unicode=True)

        # 启动 Clash 进程
        # stderr=subprocess.PIPE 允许我们捕获 Clash 的错误输出
        proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await asyncio.sleep(2) # 给予 Clash 启动时间

        # 检查 Clash 进程是否已退出（启动失败）
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=1) # 尝试读取剩余输出
            result['error'] = (f"Clash 启动失败. 退出码: {proc.returncode}, "
                               f"标准输出: {stdout.decode(errors='ignore').strip()}, "
                               f"标准错误: {stderr.decode(errors='ignore').strip()}")
            logger.error(result['error'])
            return result

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
                else:
                    result['error'] = f"HTTP 状态码: {response.status}"
        except aiohttp.client_exceptions.ProxyConnectionError as e:
            result['error'] = f"代理连接失败: {e}"
        except aiohttp.client_exceptions.ClientConnectorError as e:
            result['error'] = f"客户端连接错误: {e}"
        except asyncio.TimeoutError:
            result['error'] = "测试超时"
        except Exception as e:
            result['error'] = str(e)
            
        # 如果代理不可用，尝试从 Clash 进程的标准错误输出中获取更多信息
        if result['status'] == '不可用' and proc.poll() is None: # 仅当 Clash 仍在运行时
            try:
                # 给 Clash 一些时间写入日志，然后尝试读取其错误输出
                await asyncio.sleep(1) 
                stdout, stderr = proc.communicate(timeout=1)
                clash_log = stderr.decode(errors='ignore').strip()
                if clash_log:
                    result['error'] += f" | Clash 日志: {clash_log}"
            except subprocess.TimeoutExpired:
                proc.kill() # 如果超时，则强制终止进程
                stdout, stderr = proc.communicate()
                clash_log = stderr.decode(errors='ignore').strip()
                if clash_log:
                    result['error'] += f" | Clash 日志 (强制终止): {clash_log}"
            except Exception as log_e:
                result['error'] += f" | 读取 Clash 日志失败: {log_e}"

    except FileNotFoundError:
        result['error'] = f"Clash 可执行文件未找到: {clash_bin}. 请确保路径正确且文件可执行。"
    except Exception as e:
        result['error'] = f"启动 Clash 或配置生成失败: {str(e)}"
    finally:
        # 确保 Clash 进程被终止
        if proc and proc.poll() is None: # 检查进程是否仍在运行
            proc.terminate() # 尝试正常终止
            try:
                await asyncio.wait_for(proc.wait(), timeout=1) # 等待进程终止
            except asyncio.TimeoutError:
                proc.kill() # 如果超时，则强制杀死进程
        # 删除临时配置文件
        if config_path and os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception as e:
                logger.warning(f"删除配置文件 {config_path} 失败: {e}")
    
    logger.info(f"🔒 {proxy.get('type', 'UNKNOWN').upper()}-{proxy.get('network', 'TCP').upper()}-{'TLS' if proxy.get('sni') else 'NA'} "
                f"{proxy.get('name', 'Unnamed')}: {result['status']}, 延迟: {result['latency']:.2f}ms")
    return result

async def main():
    """主函数，运行代理测试"""
    parser = argparse.ArgumentParser(description='测试代理节点')
    parser.add_argument('--proxy-url', default='https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt',
                        help='代理节点 URL')
    parser.add_argument('--clash-bin', default='./tools/clash', help='Clash 二进制路径')
    # 调整批量测试节点数，通常不宜过高，避免资源耗尽
    parser.add_argument('--batch-size', type=int, default=max(10, psutil.cpu_count() * 2), help='批量测试节点数') 
    parser.add_argument('--invalid-file', default='data/invalid_nodes.yaml', help='不可用节点文件')
    parser.add_argument('--valid-file', default='data/521.yaml', help='可用节点文件')
    parser.add_argument('--expire-days', type=int, default=7, help='不可用节点过期天数')
    args = parser.parse_args()

    os.makedirs('data', exist_ok=True)
    
    # 加载上次的不可用和可用节点
    invalid_nodes = load_invalid_nodes(args.invalid_file)
    valid_nodes = load_invalid_nodes(args.valid_file)
    
    # 过滤掉任何无法生成有效键的节点（例如，格式错误的节点）
    invalid_keys = {get_node_key(node) for node in invalid_nodes if get_node_key(node)}
    valid_keys = {get_node_key(node) for node in valid_nodes if get_node_key(node)}

    async with aiohttp.ClientSession() as session:
        # 获取最新节点
        proxies = await fetch_proxies(args.proxy_url)
        if not proxies:
            logger.error("没有可测试的代理节点")
            return

        # 过滤新增节点，确保只有有效的且未曾测试过的节点被加入
        new_proxies = [p for p in proxies if get_node_key(p) and get_node_key(p) not in invalid_keys and get_node_key(p) not in valid_keys]
        logger.info(f"总节点数: {len(proxies)}, 新增节点: {len(new_proxies)}, 已知可用: {len(valid_nodes)}, 已知不可用: {len(invalid_nodes)}")

        # 测试新增节点
        results = []
        base_port = get_free_port()
        for i in range(0, len(new_proxies), args.batch_size):
            batch = new_proxies[i:i + args.batch_size]
            # 为批处理中的每个 Clash 实例确保唯一的端口，避免冲突
            tasks = [test_proxy(proxy, session, args.clash_bin, base_port + (j + i) * 3) for j, proxy in enumerate(batch)]
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)

        # 合并结果并进行去重
        new_valid = [r['proxy'] for r in results if r['status'] == '可用']
        new_invalid = [r['proxy'] for r in results if r['status'] == '不可用']
        
        # 更新可用节点（保留旧的可用节点 + 新测试的可用节点）
        # 使用字典进行去重，键是节点唯一标识
        all_valid_temp = {}
        for node in valid_nodes:
            key = get_node_key(node)
            if key:
                all_valid_temp[key] = node
        for node in new_valid:
            key = get_node_key(node)
            if key:
                all_valid_temp[key] = node
        all_valid = list(all_valid_temp.values())

        # 更新不可用节点（保留未过期的旧节点 + 新测试的不可用节点）
        expire_time = datetime.now() - timedelta(days=args.expire_days)
        all_invalid_temp = {}
        for node in invalid_nodes:
            key = get_node_key(node)
            # 仅保留未过期的旧不可用节点
            if key and 'tested_at' in node and datetime.fromisoformat(node['tested_at']) > expire_time:
                all_invalid_temp[key] = node
        for node in new_invalid:
            key = get_node_key(node)
            if key:
                all_invalid_temp[key] = node
        all_invalid = list(all_invalid_temp.values())

        # 保存结果
        await save_nodes(args.valid_file, all_valid)
        await save_nodes(args.invalid_file, all_invalid)

        # 输出统计信息
        if proxies: # 避免除以零
            logger.info(f"测试完成: 总节点数={len(proxies)}, 可用节点={len(all_valid)}, "
                        f"不可用节点={len(all_invalid)}, 可用率={len(all_valid)/len(proxies)*100:.2f}%")
        else:
            logger.info(f"测试完成: 没有代理节点可供测试。")

if __name__ == '__main__':
    asyncio.run(main())
