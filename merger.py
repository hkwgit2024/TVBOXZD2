import json
import os
import sys
import logging
from typing import List, Dict, Any

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def merge_tvbox_configs(source_dir: str, output_file: str) -> None:
    """
    遍历指定目录下的所有 JSON 文件，合并 TVbox 的配置数据，并保存到新文件。
    """
    sites = []
    lives = []
    spider = []
    
    # 获取目录下的所有文件
    file_list = [f for f in os.listdir(source_dir) if f.endswith('.json')]
    
    if not file_list:
        logger.warning(f"目录 '{source_dir}' 中没有找到任何 JSON 文件。")
        return

    logger.info(f"开始处理 {len(file_list)} 个 JSON 文件...")
    
    for file_name in file_list:
        file_path = os.path.join(source_dir, file_name)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # 提取 sites 配置
                if 'sites' in data and isinstance(data['sites'], list):
                    sites.extend(data['sites'])
                
                # 提取 lives 配置
                if 'lives' in data and isinstance(data['lives'], list):
                    lives.extend(data['lives'])
                    
                # 提取 spider 配置，只保留第一个找到的
                if not spider and 'spider' in data and isinstance(data['spider'], str):
                    spider.append(data['spider'])
                    
                logger.info(f"成功处理文件：{file_name}")
        except json.JSONDecodeError:
            logger.error(f"文件 '{file_name}' 格式不正确，已跳过。")
        except Exception as e:
            logger.error(f"处理文件 '{file_name}' 时发生错误：{e}")

    # 构建合并后的新配置
    merged_data = {
        "sites": sites,
        "lives": lives,
        "spider": spider[0] if spider else ""
    }
    
    # 保存合并后的 JSON 文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, ensure_ascii=False, indent=2)
        logger.info(f"所有配置已成功合并并保存到 '{output_file}' 文件。")
    except Exception as e:
        logger.error(f"保存合并文件时发生错误：{e}")

if __name__ == "__main__":
    SOURCE_DIRECTORY = "box"
    OUTPUT_FILE = "merged_tvbox_config.json"
    merge_tvbox_configs(SOURCE_DIRECTORY, OUTPUT_FILE)
