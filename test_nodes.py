import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
from typing import Dict, List
from yaml import SafeLoader

# --- 自定义 YAML 构造函数 ---
def str_constructor(loader, node):
    return str(node.value)

SafeLoader.add_constructor('!str', str_constructor)

# --- 节点格式验证函数 ---
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

# --- 测试代理节点函数 ---
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

    proc = None # 初始化进程变量
    result = {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': None}
    
    # --- 增加 Clash/Mihomo 启动尝试和健康检查 ---
    max_clash_startup_retries = 3
    clash_startup_delay = 5 # 每次启动等待时间
    clash_api_url = f'http://127.0.0.1:{clash_port}/proxies' # Clash/Mihomo API，用于健康检查

    for attempt in range(max_clash_startup_retries):
        proc = subprocess.Popen([clash_bin, '-f', config_path, '-d', 'temp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # '-d temp' 参数让 Clash/Mihomo 将日志和缓存放在 temp 目录下，保持主目录干净
        
        await asyncio.sleep(clash_startup_delay) # 延长等待时间

        # 尝试连接API端口进行健康检查
        try:
            async with session.get(clash_api_url, timeout=3) as api_response:
                if api_response.status == 200:
                    # API 可达，说明 Clash/Mihomo 已启动
                    print(f"  {proxy_name}: Clash/Mihomo 核心启动成功 (尝试 {attempt + 1}/{max_clash_startup_retries})")
                    break # 成功启动，跳出重试循环
                else:
                    print(f"  {proxy_name}: Clash/Mihomo API 响应异常 {api_response.status} (尝试 {attempt + 1}/{max_clash_startup_retries})")
        except Exception as e:
            print(f"  {proxy_name}: Clash/Mihomo API 连接失败: {e} (尝试 {attempt + 1}/{max_clash_startup_retries})")
        
        # 如果当前尝试失败，终止旧进程并准备下一次尝试
        if proc:
            proc.terminate()
            await asyncio.sleep(1) # 给进程一些时间终止
            proc.kill() # 确保进程被杀死
            await asyncio.sleep(0.5)

    if proc is None or proc.poll() is not None: # 如果进程未启动或已终止
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': "Clash/Mihomo 核心未能成功启动"}

    # --- 增加测试重试机制 ---
    max_test_retries = 2
    test_timeout = 10 # 延长测试超时时间
    success = False

    for attempt in range(max_test_retries):
        try:
            start_time = time.time()
            # 优先测试 HTTP 代理
            async with session.get(
                'http://www.google.com/generate_204', # 使用一个轻量且稳定的测试URL
                proxy=f'http://127.0.0.1:{clash_port}',
                timeout=test_timeout
            ) as response:
                if response.status == 204: # google.com/generate_204 返回 204 No Content
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000  # 毫秒
                    success = True
                    break
        except Exception as e:
            # 如果 HTTP 测试失败，尝试 SOCKS5
            try:
                start_time_socks5 = time.time() # 重新计时 SOCKS5
                async with session.get(
                    'http://www.google.com/generate_204',
                    proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                    timeout=test_timeout
                ) as response:
                    if response.status == 204:
                        result['status'] = '可用'
                        result['latency'] = (time.time() - start_time_socks5) * 1000  # 毫秒
                        success = True
                        break
            except Exception as socks5_e:
                result['error'] = f"测试失败 (尝试 {attempt + 1}/{max_test_retries}): HTTP ({e}) / SOCKS5 ({socks5_e})"
                if attempt < max_test_retries - 1:
                    await asyncio.sleep(5) # 失败后等待片刻再重试
                continue # 继续下一次重试循环
        
        if success:
            break # 如果测试成功，跳出重试循环

    finally:
        # --- 清理 Clash/Mihomo 进程和文件 ---
        if proc:
            try:
                proc.terminate()
                await asyncio.sleep(1)
                if proc.poll() is None: # 如果进程仍在运行，强制杀死
                    proc.kill()
            except ProcessLookupError:
                pass # 进程可能已经结束

        try:
            os.remove(config_path)
            # 清理 Clash/Mihomo 在 temp 目录生成的额外文件（如geoip.dat等）
            for f in os.listdir('temp'):
                if f.startswith(f"config_{proxy_name}") or f.endswith(".dat"): # 更精确的清理规则
                    try:
                        os.remove(os.path.join('temp', f))
                    except OSError:
                        pass # 文件可能不存在或正在被使用
        except OSError:
            pass # 文件可能不存在

    return result

# --- 主函数 ---
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
        # 注意：这里的 batch_size = 50 意味着同时启动 50 个 Clash/Mihomo 实例。
        # 在 GitHub Actions 上可能对资源造成较大压力。
        # 如果仍然出现不稳定的情况，可以尝试降低 batch_size，例如 10-20。
        batch_size = 20 # 降低批处理大小，减少并发实例数
        
        # 使用 asyncio.Semaphore 进一步控制并发，即使 batch_size 较大
        # 例如，限制同时运行的 test_proxy 任务不超过 10 个
        semaphore = asyncio.Semaphore(10) # 控制同时测试的节点数量

        tasks = []
        for proxy in valid_proxies:
            async def limited_test():
                async with semaphore:
                    return await test_proxy(proxy, session, './tools/clash')
            tasks.append(limited_test())
        
        # 收集所有结果
        all_results = []
        # 使用 tqdm 或其他方式显示进度（可选，但在GH Actions日志中效果有限）
        for i, future in enumerate(asyncio.as_completed(tasks)):
            result = await future
            if isinstance(result, dict):
                all_results.append(result)
                with open('data/521.yaml', 'a') as f:
                    yaml.dump([result], f, allow_unicode=True, indent=2) # 增加 indent 提高可读性
                print(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''}{'，错误: ' + result['error'] if result['error'] else ''}")
            else:
                # 处理异常，例如 asyncio.CancelledError
                print(f"任务完成异常: {result}")

if __name__ == "__main__":
    asyncio.run(main())
