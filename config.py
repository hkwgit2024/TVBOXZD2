
import yaml
import copy
from datetime import datetime
import logging
from typing import Dict, List, Any
from node import Node, b64encodes
from config import config

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

def generate_configs(merged: Dict[int, Node], unknown: Set[str], sources_obj: List['Source']) -> None:
    """生成 Clash 和 V2Ray 配置文件"""
    output_manager = OutputManager()
    
    # V2Ray 订阅
    txt = ""
    unsupports = 0
    for hashp, p in merged.items():
        try:
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

    # ... 其他配置生成逻辑

