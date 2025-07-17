
import os
import logging
import datetime
from typing import Set, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from node import Node, NotANode, UnsupportedType
from source import Source
from config import config
from config import generate_configs

logger = logging.getLogger(__name__)

def setup_logging():
    logging.basicConfig(
        filename='fetch.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def raw2fastly(url: str) -> str:
    if not os.path.exists("local_proxy.conf"):
        return url
    if url.startswith("https://raw.githubusercontent.com/"):
        return "https://ghfast.top/" + url
    return url

def extract(url: str) -> Union[Set[str], int]:
    try:
        res = requests.get(url, timeout=(config["fetch_timeout"]["connect"], config["fetch_timeout"]["read"]))
        if res.status_code != 200:
            return res.status_code
        urls: Set[str] = set()
        mark = '#' + url.split('#', 1)[1] if '#' in url else ''
        for line in res.text.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line + mark)
            elif '://' in line:
                urls.add(line)
        return urls
    except requests.exceptions.RequestException as e:
        logger.error(f"提取 '{url}' 失败：{e}")
        return -1

def merge(source_obj: Source, sourceId: int, merged: Dict[int, Node], unknown: Set[str]) -> None:
    if not source_obj.sub:
        logger.info(f"空订阅 '{source_obj.url}'，跳过")
        return
    for p in source_obj.sub:
        if isinstance(p, str) and '://' not in p:
            continue
        try:
            n = Node(p)
            n.format_name()
            Node.names.add(n.data['name'])
            hashn = hash(n)
            if hashn not in merged:
                merged[hashn] = n
            else:
                merged[hashn].data.update(n.data)
            # ... 其他合并逻辑
        except (UnsupportedType, NotANode) as e:
            unknown.add(str(p))
            logger.error(f"节点错误：{e}")
        except Exception as e:
            logger.error(f"解析节点失败：{e}")

def main():
    setup_logging()
    logger.info("开始执行 Proxy Fetch")

    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if os.path.exists("local_NO_NODES"):
        logger.warning("已启用无节点调试模式")
        sources = []

    # 处理动态链接
    from dynamic import AUTOURLS, AUTOFETCH
    if not os.path.exists("local_NO_DYNAMIC"):
        for auto_fun in AUTOURLS:
            logger.info(f"生成动态链接 '{auto_fun.__name__}'")
            try:
                url = auto_fun()
                if url:
                    if isinstance(url, str):
                        sources.append(url)
                    elif isinstance(url, (list, tuple, set)):
                        sources.extend(url)
                    logger.info("动态链接生成成功")
                else:
                    logger.info("跳过空动态链接")
            except Exception as e:
                logger.error(f"动态链接生成失败：{e}")

    # 整理链接
    sources_final: Set[str] = set()
    airports: Set[str] = set()
    for source in sources:
        if source == 'EOF':
            break
        if not source or source[0] == '#':
            continue
        sub = source[1:] if source[0] == '!' and os.path.exists("local_proxy.conf") else source
        isairport = sub[0] == '*'
        sub = sub[1:] if isairport else sub
        if sub[0] == '+':
            sub = ' '.join(sub.split()[:-1]) + ' ' + raw2fastly(sub.split()[-1])
        else:
            sub = raw2fastly(sub)
        (airports if isairport else sources_final).add(sub)

    # 抓取机场列表
    if airports:
        logger.info("抓取机场列表")
        with ThreadPoolExecutor(max_workers=min(os.cpu_count() * 2, 10)) as executor:
            future_to_url = {executor.submit(extract, sub): sub for sub in airports}
            for future in as_completed(future_to_url):
                sub = future_to_url[future]
                logger.info(f"合并 '{sub}'")
                try:
                    res = future.result()
                    if isinstance(res, int):
                        logger.error(f"抓取失败：{res}")
                    else:
                        sources_final.update(res)
                        logger.info("完成")
                except Exception as e:
                    logger.error(f"合并失败：{e}")

    # 抓取和合并节点
    sources_obj = [Source(url) for url in sorted(sources_final) + AUTOFETCH]
    merged: Dict[int, Node] = {}
    unknown: Set[str] = set()

    with ThreadPoolExecutor(max_workers=min(os.cpu_count() * 2, 10)) as executor:
        future_to_source = {executor.submit(source.get): source for source in sources_obj}
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            logger.info(f"抓取 '{source.url}'")
            try:
                future.result()
                source.parse()
                merge(source, sources_obj.index(source), merged, unknown)
                logger.info("完成")
            except Exception as e:
                logger.error(f"处理 '{source.url}' 失败：{e}")

    # 处理 STOP 模式
    if os.path.exists("local_NO_NODES") or (datetime.now().month, datetime.now().day) in ((6, 4), (7, 1), (10, 1)):
        merged = {i: Node(nd) for i, nd in enumerate(config["stop_fake_nodes"].splitlines())}

    # 生成配置文件
    generate_configs(merged, unknown, sources_obj)

    logger.info("任务完成")

if __name__ == '__main__':
    main()

