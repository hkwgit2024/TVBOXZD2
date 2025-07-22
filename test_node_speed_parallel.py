import yaml
import speedtest
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
from operator import itemgetter

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_node_speed_sync(proxy):
    """同步测试单个节点的下载速度"""
    try:
        s = speedtest.Speedtest()
        s.get_best_server()
        download_speed = s.download() / 1000000  # 转换为 Mbps
        logger.info(f"节点 {proxy['name']} 测试完成，下载速度: {download_speed:.2f} Mbps")
        return {'name': proxy['name'], 'speed': download_speed, 'config': proxy}
    except Exception as e:
        logger.error(f"测试节点 {proxy['name']} 失败: {str(e)}")
        return {'name': proxy['name'], 'speed': 0, 'config': proxy}

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
    max_workers = min(len(proxies), 5)  # 限制最大并行数以避免过载
    async with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = [test_node_speed(proxy, executor) for proxy in proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # 过滤掉测试失败的节点并按速度排序
    valid_results = [r for r in results if isinstance(r, dict) and r['speed'] > 0]
    sorted_results = sorted(valid_results, key=itemgetter('speed'), reverse=True)

    # 准备新的配置文件
    new_config = config.copy()
    new_config['proxies'] = [result['config'] for result in sorted_results]

    # 保存结果到新的 YAML 文件
    try:
        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yaml.safe_dump(new_config, f, allow_unicode=True, sort_keys=False)
        logger.info("测试结果已保存到 clash.yaml")
        
        # 打印测试结果
        logger.info("\n测试结果（按速度从快到慢）：")
        for result in sorted_results:
            logger.info(f"节点: {result['name']}, 速度: {result['speed']:.2f} Mbps")
    except Exception as e:
        logger.error(f"保存结果失败: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
