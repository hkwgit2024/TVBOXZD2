import yaml
import copy
import os
from datetime import datetime
import logging
from typing import Dict, List, Any, Set
from node import Node, b64encodes

logger = logging.getLogger(__name__)

class OutputManager:
    """管理文件输出"""
    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def write_file(self, filename: str, content: str, encoding: str = "utf-8") -> None:
        try:
            with open(os.path.join(self.output_dir, filename), 'w', encoding=encoding) as f:
                f.write(content)
            logger.info(f"成功写入文件：{filename}")
        except Exception as e:
            logger.error(f"写入文件 {filename} 失败：{e}")

def generate_configs(merged: Dict[int, Node], unknown: Set[str], sources_obj: List['Source'], used: Dict[int, Dict[int, str]]) -> None:
    """生成 Clash 和 V2Ray 配置文件"""
    output_manager = OutputManager()
    
    # V2Ray 订阅
    txt = ""
    unsupports = 0
    for hashp, p in merged.items():
        try:
            if hashp in used:
                p.data['name'] = ','.join([str(_) for _ in sorted(list(used[hashp]))]) + '|' + p.data['name']
            if p.supports_ray():
                txt += p.url + '\n'
            else:
                unsupports += 1
        except Exception as e:
            logger.error(f"生成 V2Ray 节点失败：{e}")
            unsupports += 1
    for p in unknown:
        txt += p + '\n'
    
    logger.info(f"共有 {len(merged) - unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，{unsupports} 个不被 V2Ray 支持")
    output_manager.write_file("list_raw.txt", txt)
    output_manager.write_file("list.txt", b64encodes(txt))

    # Clash 配置
    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)
    
    rules: Dict[str, str] = {}
    if not os.path.exists("local_NO_ADBLOCK"):
        from adblock import merge_adblock
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)
    else:
        logger.warning("已关闭 Adblock 规则抓取")

    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    ctg_nodes_meta: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}
    try:
        with open("snippets/_config.yml", encoding="utf-8") as f:
            snip_conf = yaml.full_load(f)
    except (OSError, yaml.YAMLError) as e:
        logger.error(f"片段配置读取失败：{e}")
    else:
        logger.info("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories:
            ctg_nodes[ctg] = []
            ctg_nodes_meta[ctg] = []
        for node in merged.values():
            if node.supports_meta():
                ctgs: List[str] = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    if node.supports_clash():
                        ctg_nodes[ctgs[0]].append(node.clash_data)
                    ctg_nodes_meta[ctgs[0]].append(node.clash_data)
        for ctg, proxies in ctg_nodes.items():
            output_manager.write_file(f"snippets/nodes_{ctg}.yml", yaml.dump({'proxies': proxies}, allow_unicode=True))
        for ctg, proxies in ctg_nodes_meta.items():
            output_manager.write_file(f"snippets/nodes_{ctg}.meta.yml", yaml.dump({'proxies': proxies}, allow_unicode=True))

    logger.info("正在写出 Clash & Meta 订阅...")
    keywords: List[str] = []
    suffixes: List[str] = []
    match_rule = None
    for rule in conf['rules']:
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
            if rtype == 'DOMAIN-KEYWORD':
                keywords.append(rargument)
            elif rtype == 'DOMAIN-SUFFIX':
                suffixes.append(rargument)
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ',' + rresolve
        else:
            logger.error(f"规则 '{rule}' 无法被解析！")
            continue
        for kwd in keywords:
            if kwd in rargument and kwd != rargument:
                logger.info(f"{rargument} 已被 KEYWORD {kwd} 命中")
                break
        else:
            for sfx in suffixes:
                if ('.' + rargument).endswith('.' + sfx) and sfx != rargument:
                    logger.info(f"{rargument} 已被 SUFFIX {sfx} 命中")
                    break
            else:
                k = rtype + ',' + rargument
                if k not in rules:
                    rules[k] = rpolicy
    conf['rules'] = [','.join(_) for _ in rules.items()] + [match_rule]

    global_fp: Optional[str] = conf.get('global-client-fingerprint', None)
    proxies: List[Node.DATA_TYPE] = []
    proxies_meta: List[Node.DATA_TYPE] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash: List[str] = []
    names_clash_meta: List[str] = []
    for p in merged.values():
        if p.supports_meta():
            if 'client-fingerprint' in p.data and p.data['client-fingerprint'] == global_fp:
                del p.data['client-fingerprint']
            proxies_meta.append(p.clash_data)
            names_clash_meta.append(p.data['name'])
            if p.supports_clash():
                proxies.append(p.clash_data)
                names_clash.append(p.data['name'])
    conf['proxies'] = proxies
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload:
                    disp['proxies'] = ['REJECT']
                else:
                    disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    try:
        dns_mode: Optional[str] = conf['dns']['enhanced-mode']
    except:
        dns_mode: Optional[str] = None
    else:
        conf['dns']['enhanced-mode'] = 'fake-ip'
    output_manager.write_file("list.yml", datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n') + yaml.dump(conf, allow_unicode=True).replace('!!str ', ''))
    output_manager.write_file("snippets/nodes.yml", yaml.dump({'proxies': proxies}, allow_unicode=True).replace('!!str ', ''))

    conf_meta = copy.deepcopy(conf)
    conf_meta['proxies'] = proxies_meta
    for group in conf_meta['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash_meta
    if snip_conf:
        conf_meta['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf_meta['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes_meta.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload:
                    disp['proxies'] = ['REJECT']
                else:
                    disp['proxies'] = [_['name'] for _ in payload]
                conf_meta['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    if dns_mode:
        conf_meta['dns']['enhanced-mode'] = dns_mode
    output_manager.write_file("list.meta.yml", datetime.now().strftime('# Update: %Y-%m-%d %H:%M\n') + yaml.dump(conf_meta, allow_unicode=True).replace('!!str ', ''))
    output_manager.write_file("snippets/nodes.meta.yml", yaml.dump({'proxies': proxies_meta}, allow_unicode=True).replace('!!str ', ''))

    if snip_conf:
        logger.info("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {rpolicy: [] for rpolicy in name_map.values()}
        for rule, rpolicy in rules.items():
            if ',' in rpolicy:
                rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            output_manager.write_file(f"snippets/{name}.yml", yaml.dump({'payload': payload}, allow_unicode=True))

    logger.info("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try:
            out += f"{len(source.sub)}"
        except:
            out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    output_manager.write_file("list_result.csv", out)
