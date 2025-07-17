import requests
import logging
from typing import Dict, List, Set
from settings import config

logger = logging.getLogger(__name__)

class DomainTree:
    """域名树，用于存储和处理域名规则"""
    def __init__(self) -> None:
        self.children: Dict[str, 'DomainTree'] = {}
        self.here: bool = False

    def insert(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]) -> None:
        if not segs:
            self.here = True
            return
        if segs[0] not in self.children:
            self.children[segs[0]] = DomainTree()
        self.children[segs[0]]._insert(segs[1:])

    def remove(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._remove(segs)

    def _remove(self, segs: List[str]) -> None:
        self.here = False
        if not segs:
            self.children.clear()
            return
        if segs[0] in self.children:
            self.children[segs[0]]._remove(segs[1:])

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here:
                ret.append(name)
            else:
                ret.extend([_ + '.' + name for _ in child.get()])
        return ret

def merge_adblock(adblock_name: str, rules: Dict[str, str]) -> None:
    """合并广告拦截规则"""
    logger.info("正在解析 Adblock 列表...")
    blocked: Set[str] = set()
    unblock: Set[str] = set()

    for url in config["abf_urls"]:
        url = raw2fastly(url)
        try:
            res = session.get(url, timeout=(config["fetch_timeout"]["connect"], config["fetch_timeout"]["read"]))
            if res.status_code != 200:
                logger.error(f"{url} 下载失败：{res.status_code}")
                continue
            for line in res.text.strip().splitlines():
                line = line.strip()
                if not line or line[0] in '!#':
                    continue
                elif line[:2] == '@@':
                    unblock.add(line.split('^')[0].strip('@|^'))
                elif line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                        (line[-1] == '^' or line.endswith("$all")):
                    blocked.add(line.strip('al').strip('|^$'))
        except requests.exceptions.RequestException as e:
            logger.error(f"{url} 下载失败：{e}")
            continue

    for url in config["abf_white"]:
        url = raw2fastly(url)
        try:
            res = session.get(url, timeout=(config["fetch_timeout"]["connect"], config["fetch_timeout"]["read"]))
            if res.status_code != 200:
                logger.error(f"{url} 下载失败：{res.status_code}")
                continue
            for line in res.text.strip().splitlines():
                line = line.strip()
                if not line or line[0] == '!':
                    continue
                unblock.add(line.split('^')[0].strip('|^'))
        except requests.exceptions.RequestException as e:
            logger.error(f"{url} 下载失败：{e}")
            continue

    domain_root = DomainTree()
    domain_keys: Set[str] = set()
    for domain in blocked:
        if '/' in domain:
            continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.', '').isdigit():
            for seg in segs:
                if not seg or (seg[0] == '0' and seg != '0'):
                    break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)

    for domain in unblock:
        domain_root.remove(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain:
                break
        else:
            rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    logger.info(f"共有 {len(rules)} 条规则")
