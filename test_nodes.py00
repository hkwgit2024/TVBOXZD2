import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
import base64
import json
from typing import Dict, List
from urllib.parse import urlparse, parse_qs
from yaml import SafeLoader

# 自定义 YAML 构造函数，处理 !<str> 标签
def str_constructor(loader, node):
    return str(node.value)

# 注册自定义构造函数
SafeLoader.add_constructor('!str', str_constructor)

def validate_proxy(proxy: Dict, index: int) -> tuple[bool, str]:
    """验证代理节点格式，返回 (是否有效, 错误信息)"""
    required_fields = {
        'name': str,
        'server': str,
        'port': int,
        'type': str
    }
    protocol_specific_fields = {
        'trojan': [('password', str)],
        'vmess': [('uuid', str)],
        'vless': [('uuid', str)],
        'ss': [('cipher', str), ('password', str)],
        'hysteria2': [('password', str)]
    }

    # 检查必要字段
    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"节点 {index} 缺少字段: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"节点 {index} 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # 检查协议特定字段
    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"节点 {index} ({proxy_type}) 缺少字段: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"节点 {index} ({proxy_type}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # 检查 name 唯一性（简单检查，实际应在全局验证）
    if not proxy['name'].strip():
        return False, f"节点 {index} name 为空"

    return True, ""

async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    """测试单个代理节点，返回结果"""
    proxy_name = proxy.get('name', 'unknown')
    print(f"测试代理节点: {proxy_name}")

    # 写入临时 Clash 配置文件
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'mode': 'global',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy_name]}],
        'rules': ['MATCH,auto']
    }
    os.makedirs('temp', exist_ok=True)
    config_path = f'temp/config_{proxy_name}.yaml'
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': f"写入配置失败: {str(e)}"}

    # 启动 Clash
    proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    await asyncio.sleep(2)  # 等待 Clash 启动

    result = {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': None}
    try:
        start_time = time.time()
        # 测试 HTTP 代理
        async with session.get(
            'http://www.google.com',
            proxy=f'http://127.0.0.1:{clash_port}',
            timeout=5
        ) as response:
            if response.status == 200:
                result['status'] = '可用'
                result['latency'] = (time.time() - start_time) * 1000  # 毫秒
    except Exception:
        try:
            # 回退测试 SOCKS5 代理（适用于 trojan, hysteria2 等）
            async with session.get(
                'http://www.google.com',
                proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                timeout=5
            ) as response:
                if response.status == 200:
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000  # 毫秒
        except Exception as e:
            result['error'] = f"测试失败: {str(e)}"
    finally:
        proc.terminate()
        try:
            os.remove(config_path)
        except:
            pass
    return result

def parse_proxy_line(line: str) -> Dict:
    """解析单行代理配置，返回代理字典"""
    line = line.strip()
    if not line:
        return None

    try:
        url_parts = urlparse(line)
        scheme = url_parts.scheme.lower()
        proxy = {'name': url_parts.fragment or f"{scheme}_node_{url_parts.netloc}"}

        if scheme == 'ss':
            # Shadowsocks: ss://<base64_encoded_data>@<server>:<port>#<name>
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) == 2:
                server_port = auth_data[1].split(':')
                if len(server_port) != 2:
                    return None
                proxy['type'] = 'ss'
                proxy['server'] = server_port[0]
                proxy['port'] = int(server_port[1])
                # 解码 Base64 数据
                decoded = base64.urlsafe_b64decode(auth_data[0] + '==' * (-len(auth_data[0]) % 4)).decode('utf-8')
                cipher_password = decoded.split(':')
                if len(cipher_password) != 2:
                    return None
                proxy['cipher'] = cipher_password[0]
                proxy['password'] = cipher_password[1]
            else:
                return None

        elif scheme == 'ssr':
            # ShadowsocksR: ssr://<base64_encoded_data>
            decoded = base64.urlsafe_b64decode(line[6:] + '==' * (-len(line[6:]) % 4)).decode('utf-8')
            parts = decoded.split(':')
            if len(parts) < 6:
                return None
            proxy['type'] = 'ss'
            proxy['server'] = parts[0]
            proxy['port'] = int(parts[1])
            proxy['cipher'] = parts[3]
            proxy['password'] = base64.urlsafe_b64decode(parts[5].split('/')[0] + '==' * (-len(parts[5].split('/')[0]) % 4)).decode('utf-8')
            params = parse_qs(url_parts.query)
            proxy['name'] = base64.urlsafe_b64decode(params.get('remarks', [''])[0] + '==' * (-len(params.get('remarks', [''])[0]) % 4)).decode('utf-8') if 'remarks' in params else proxy['name']

        elif scheme == 'vmess':
            # VMess: vmess://<base64_encoded_json>
            decoded = base64.urlsafe_b64decode(line[8:] + '==' * (-len(line[8:]) % 4)).decode('utf-8')
            vmess_config = json.loads(decoded)
            proxy['type'] = 'vmess'
            proxy['server'] = vmess_config.get('add')
            proxy['port'] = int(vmess_config.get('port'))
            proxy['uuid'] = vmess_config.get('id')
            proxy['alterId'] = int(vmess_config.get('aid', 0))
            proxy['cipher'] = vmess_config.get('scy', 'auto')
            proxy['network'] = vmess_config.get('net', 'tcp')
            proxy['tls'] = vmess_config.get('tls') == 'tls'
            proxy['name'] = vmess_config.get('ps', proxy['name'])
            if proxy['network'] == 'ws':
                proxy['ws-opts'] = {
                    'path': vmess_config.get('path', '/'),
                    'headers': {'Host': vmess_config.get('host', '')}
                }
            if proxy['tls']:
                proxy['servername'] = vmess_config.get('sni', '')

        elif scheme == 'vless':
            # VLESS: vless://<uuid>@<server>:<port>?<params>#<name>
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                return None
            proxy['type'] = 'vless'
            proxy['uuid'] = auth_data[0]
            server_port = auth_data[1].split(':')
            if len(server_port) != 2:
                return None
            proxy['server'] = server_port[0]
            proxy['port'] = int(server_port[1])
            params = parse_qs(url_parts.query)
            proxy['encryption'] = params.get('encryption', ['none'])[0]
            proxy['security'] = params.get('security', ['none'])[0]
            proxy['type'] = params.get('type', ['tcp'])[0]
            if proxy['type'] == 'ws':
                proxy['ws-opts'] = {
                    'path': params.get('path', ['/'])[0],
                    'headers': {'Host': params.get('host', [''])[0]}
                }
            if proxy['security'] == 'tls':
                proxy['servername'] = params.get('sni', [''])[0]

        elif scheme == 'trojan':
            # Trojan: trojan://<password>@<server>:<port>?<params>#<name>
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                return None
            proxy['type'] = 'trojan'
            proxy['password'] = auth_data[0]
            server_port = auth_data[1].split(':')
            if len(server_port) != 2:
                return None
            proxy['server'] = server_port[0]
            proxy['port'] = int(server_port[1])
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            proxy['network'] = params.get('type', ['tcp'])[0]
            if proxy['network'] == 'grpc':
                proxy['grpc-opts'] = {'grpc-service-name': params.get('serviceName', [''])[0]}
            proxy['skip-cert-verify'] = params.get('allowInsecure', ['0'])[0] == '1'

        elif scheme == 'hysteria2':
            # Hysteria2: hysteria2://<password>@<server>:<port>?<params>#<name>
            auth_data = url_parts.netloc.split('@')
            if len(auth_data) != 2:
                return None
            proxy['type'] = 'hysteria2'
            proxy['password'] = auth_data[0]
            server_port = auth_data[1].split(':')
            if len(server_port) != 2:
                return None
            proxy['server'] = server_port[0]
            proxy['port'] = int(server_port[1])
            params = parse_qs(url_parts.query)
            proxy['sni'] = params.get('sni', [''])[0]
            proxy['skip-cert-verify'] = params.get('insecure', ['0'])[0] == '1'
            proxy['mport'] = params.get('mport', [''])[0]
            proxy['obfs'] = params.get('obfs', ['none'])[0]

        else:
            return None

        return proxy
    except Exception as e:
        print(f"解析代理失败: {line[:50]}... 错误: {str(e)}")
        return None

async def fetch_proxies(url: str) -> List[Dict]:
    """从指定 URL 获取代理列表"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=30) as response:
                if response.status != 200:
                    print(f"获取代理列表失败，状态码: {response.status}")
                    return []
                content = await response.text()
                proxies = []
                for line in content.splitlines():
                    proxy = parse_proxy_line(line)
                    if proxy:
                        proxies.append(proxy)
                return proxies
        except Exception as e:
            print(f"获取代理列表失败: {str(e)}")
            return []

async def main():
    # 从 URL 获取代理列表
    proxy_url = 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt'
    proxies = await fetch_proxies(proxy_url)

    if not proxies:
        print("未找到代理节点")
        sys.exit(1)

    # 验证节点格式
    valid_proxies = []
    invalid_proxies = []
    for i, proxy in enumerate(proxies):
        is_valid, error = validate_proxy(proxy, i)
        if is_valid:
            valid_proxies.append(proxy)
        else:
            invalid_proxies.append({'name': proxy.get('name', f'节点_{i}'), 'error': error})

    # 记录无效节点
    if invalid_proxies:
        os.makedirs('data', exist_ok=True)
        with open('data/invalid_nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'invalid_proxies': invalid_proxies}, f, allow_unicode=True)
        print(f"发现 {len(invalid_proxies)} 个无效节点，详情见 data/invalid_nodes.yaml")

    # 创建输出文件
    os.makedirs('data', exist_ok=True)
    with open('data/521.yaml', 'w', encoding='utf-8') as f:
        f.write('results:\n')

    # 配置 aiohttp 会话
    async with aiohttp.ClientSession() as session:
        # 分批并发测试（每批 50 个节点）
        batch_size = 50
        for i in range(0, len(valid_proxies), batch_size):
            batch = valid_proxies[i:i + batch_size]
            tasks = [test_proxy(proxy, session, './tools/clash') for proxy in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 写入结果
            with open('data/521.yaml', 'a', encoding='utf-8') as f:
                for result in results:
                    if isinstance(result, dict):
                        yaml.dump([result], f, allow_unicode=True)
                        print(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''}")

if __name__ == "__main__":
    asyncio.run(main())
