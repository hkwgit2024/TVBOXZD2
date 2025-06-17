import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
from typing import Dict, List
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
        with open(config_path, 'w') as f:
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

async def main():
    # 读取 520.yaml
    try:
        with open('data/520.yaml', 'r') as f:
            config = yaml.load(f, Loader=SafeLoader)
        proxies = config.get('proxies', [])
    except yaml.YAMLError as e:
        print(f"解析 520.yaml 失败: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"读取 520.yaml 失败: {str(e)}")
        sys.exit(1)

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
        with open('data/invalid_nodes.yaml', 'w') as f:
            yaml.dump({'invalid_proxies': invalid_proxies}, f, allow_unicode=True)
        print(f"发现 {len(invalid_proxies)} 个无效节点，详情见 data/invalid_nodes.yaml")

    # 创建输出文件
    os.makedirs('data', exist_ok=True)
    with open('data/521.yaml', 'w') as f:
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
            with open('data/521.yaml', 'a') as f:
                for result in results:
                    if isinstance(result, dict):
                        yaml.dump([result], f, allow_unicode=True)
                        print(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''}")

if __name__ == "__main__":
    asyncio.run(main())
