import os
import yaml
import logging
from typing import Dict, List, Set
from node import Node
from source import Source

logger = logging.getLogger(__name__)

def generate_configs(merged: Dict[int, Node], unknown: Set[str], sources: List[Source], used: Dict[int, Dict[int, str]]) -> None:
    """生成配置文件"""
    proxies = []
    names = []
    for n in merged.values():
        proxies.append(n.data)
        names.append(n.data['name'])

    with open("list_raw.txt", "w", encoding="utf-8") as f:
        for n in names:
            f.write(f"{n}\n")

    with open("list.txt", "w", encoding="utf-8") as f:
        for n in proxies:
            if n.get('type') == 'ss':
                f.write(f"ss://{n['cipher']}:{n['password']}@{n['server']}:{n['port']}\n")
            elif n.get('type') == 'vmess':
                f.write(f"vmess://{n['uuid']}@{n['server']}:{n['port']}?encryption={n['cipher']}&type={n['network']}&path={n.get('ws-opts', {}).get('path', '')}&host={n.get('ws-opts', {}).get('headers', {}).get('Host', '')}\n")
            elif n.get('type') == 'trojan':
                f.write(f"trojan://{n['password']}@{n['server']}:{n['port']}?sni={n.get('sni', '')}\n")

    with open("list.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump({'proxies': proxies}, f, allow_unicode=True)

    with open("list.meta.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump({'proxies': proxies}, f, allow_unicode=True)

    os.makedirs("snippets", exist_ok=True)
    with open("snippets/_config.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump({'proxies': proxies[:100]}, f, allow_unicode=True)

    for i in range(0, len(proxies), 100):
        with open(f"snippets/nodes{i // 100}.yml", "w", encoding="utf-8") as f:
            yaml.safe_dump({'proxies': proxies[i:i+100]}, f, allow_unicode=True)

    with open("list_result.csv", "w", encoding="utf-8") as f:
        f.write("Name,Type,Server,Port,Cipher,Password,UUID,SNI\n")
        for n in proxies:
            f.write(f"{n['name']},{n.get('type', '')},{n.get('server', '')},{n.get('port', '')},{n.get('cipher', '')},{n.get('password', '')},{n.get('uuid', '')},{n.get('sni', '')}\n")

    try:
        with open("config.yaml", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("未找到 config.yaml 文件，将跳过基于 config.yaml 的过滤")
        cfg = {}

    banned_words = cfg.get("banned_words", "")
    with open("abpwhite.txt", "r", encoding="utf-8") as f:
        whitelist = {line.strip() for line in f if line.strip() and not line.startswith("#")}

    with open("list_raw.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    with open("list_raw.txt", "w", encoding="utf-8") as f:
        for line in lines:
            if not any(word in line for word in banned_words):
                f.write(line)

    with open("list.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    with open("list.txt", "w", encoding="utf-8") as f:
        for line in lines:
            if not any(word in line for word in banned_words):
                f.write(line)

    for i in range(0, len(proxies), 100):
        with open(f"snippets/nodes{i // 100}.yml", "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
        with open(f"snippets/nodes{i // 100}.yml", "w", encoding="utf-8") as f:
            filtered_proxies = [p for p in nodes['proxies'] if not any(word in p['name'] for word in banned_words)]
            yaml.safe_dump({'proxies': filtered_proxies}, f, allow_unicode=True)

    with open("list.yml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    filtered_proxies = [p for p in cfg['proxies'] if not any(word in p['name'] for word in banned_words)]
    with open("list.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump({'proxies': filtered_proxies}, f, allow_unicode=True)

    with open("list.meta.yml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    filtered_proxies = [p for p in cfg['proxies'] if not any(word in p['name'] for word in banned_words)]
    with open("list.meta.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump({'proxies': filtered_proxies}, f, allow_unicode=True)

    with open("list_result.csv", "r", encoding="utf-8") as f:
        lines = f.readlines()
    with open("list_result.csv", "w", encoding="utf-8") as f:
        f.write(lines[0])
        for line in lines[1:]:
            if not any(word in line for word in banned_words):
                f.write(line)
