
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

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_node_speed_sync(proxy):
    """同步测试单个节点的下载速度和延迟"""
    try:
        # 配置代理
        proxy_type = proxy.get('type', '').lower()
        if proxy_type not in ['ss', 'vmess', 'trojan']:  # 只支持部分代理类型
            logger.warning(f"节点 {proxy['name']} 的类型 {proxy_type} 不支持，跳过")
            return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'config': proxy}

        # 设置代理（以 Shadowsocks 为例，需根据代理类型调整）
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_type == 'ss' else socks.HTTP,
            proxy['server'],
            proxy['port'],
            username=proxy.get('username', ''),
            password=proxy.get('password', '')
        )
        socket.socket = socks.socksocket

        # 测试延迟
        start_time = time.time()
        try:
            conn = http.client.HTTPConnection("www.google.com", timeout=5)
            conn.request("HEAD", "/")
            conn.getresponse()
            latency = (time.time() - start_time) * 1000  # 转换为毫秒
            logger.info(f"节点 {proxy['name']} 延迟: {latency:.2f} ms")
        except Exception as e:
            logger.error(f"节点 {proxy['name']} 延迟测试失败: {str(e)}")
            return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'config': proxy}
        finally:
            conn.close()

        # 测试下载速度
        try:
            s = speedtest.Speedtest()
            s.get_best_server()
            download_speed = s.download() / 1000000  # 转换为 Mbps
            logger.info(f"节点 {proxy['name']} 下载速度: {download_speed:.2f} Mbps")
            return {'name': proxy['name'], 'speed': download_speed, 'latency': latency, 'config': proxy}
        except Exception as e:
            logger.error(f"节点 {proxy['name']} 速度测试失败: {str(e)}")
            return {'name': proxy['name'], 'speed': 0, 'latency': latency, 'config': proxy}
    except Exception as e:
        logger.error(f"测试节点 {proxy['name']} 失败: {str(e)}")
        return {'name': proxy['name'], 'speed': 0, 'latency': float('inf'), 'config': proxy}

async def test_node_speed(proxy, executor):
    """异步包装同步测试函数"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, test_node_speed_sync, proxy)

async def main():
    # 读取 Clash 配置文件
    try:
        with open('clash_config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("找不到 clash_config.yaml 文件")
        return
    except yaml.YAMLError as e:
        logger.error(f"解析 YAML 文件失败: {str(e)}")
        return

    proxies = config.get('proxies', [])
    if not proxies:
        logger.error("配置文件中没有找到 proxies 节点")
        return

    # 使用线程池进行并行测试
    max_workers = min(len(proxies), 5)  # 限制最大并行数
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        tasks = [test_node_speed(proxy, executor) for proxy in proxies]
       kowo results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        executor.shutdown(wait=True)  # 确保线程池关闭

    # 过滤掉测试失败的节点并按速度排序
    valid_results = [r for r in results if isinstance(r, dict) and r['speed'] > 0]
    sorted_results = sorted(valid_results, key=lambda x: (x['speed'], -x['latency']), reverse=True)

    # 更新节点名称，附加速度和延迟
    for result in sorted_results:
        result['config']['name'] = f"{result['name']} - {result['speed']:.2f} Mbps - {result['latency']:.2f} ms"

    # 准备新的配置文件
    new_config = config.copy()
    new_config['proxies'] = [result['config'] for result in sorted_results]

    # 保存结果到新的 YAML 文件
    try:
        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yam l.safe_dump(new_config, f, allow_unicode=True, sort_keys=False)
        logger.info("测试结果已保存到 clash.yaml")
        
        # 打印测试结果
        logger.info("\n测试结果（按速度从快到慢，延迟从小到大）：")
        for result in sorted_results:
            logger.info(f"节点: {result['config']['name']}, 速度: {result['speed']:.2f} Mbps, 延迟: {result['latency']:.2f} ms")
    except Exception as e:
        logger.error(f"保存结果失败: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
