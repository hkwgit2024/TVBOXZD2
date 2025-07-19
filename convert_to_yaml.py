import requests
import base64
import json
import yaml
import os
from urllib.parse import urlparse

# GitHub raw 链接列表
urls = [
    "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
]

# 尝试解析文本为字典（针对非 YAML/JSON 的文本格式）
def parse_text_to_dict(text):
    config = {}
    lines = text.splitlines()
    current_section = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 简单键值对解析（假设格式为 key: value 或 key=value）
        if ':' in line or '=' in line:
            separator = ':' if ':' in line else '='
            key, value = map(str.strip, line.split(separator, 1))
            if key and value:
                # 处理嵌套结构（例如 dns:）
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit():
                    value = float(value)
                elif value.startswith('[') and value.endswith(']'):
                    try:
                        value = json.loads(value)
                    except:
                        pass
                if current_section:
                    config[current_section][key] = value
                else:
                    config[key] = value
        # 处理嵌套结构的开始（例如 dns:）
        elif line.endswith(':'):
            current_section = line[:-1]
            config[current_section] = {}
    return config

# 尝试解析文件内容
def parse_content(content, url):
    try:
        # 尝试作为 YAML 解析
        config = yaml.safe_load(content)
        if config:
            return config
    except yaml.YAMLError:
        pass

    try:
        # 尝试作为 Base64 解码后解析为 JSON
        decoded = base64.b64decode(content).decode('utf-8')
        config = json.loads(decoded)
        if config:
            return config
    except (base64.binascii.Error, json.JSONDecodeError):
        pass

    # 尝试作为纯文本解析
    config = parse_text_to_dict(content)
    if config:
        return config

    raise ValueError(f"无法解析来自 {url} 的内容")

# 获取并解析所有链接的配置
def fetch_and_parse_configs(urls):
    all_configs = []
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            config = parse_content(response.text, url)
            all_configs.append(config)
        except requests.RequestException as e:
            print(f"无法获取 {url}: {e}")
        except ValueError as e:
            print(e)
    return all_configs

# 合并配置
def merge_configs(configs):
    merged = {}
    for config in configs:
        if isinstance(config, dict):
            for key, value in config.items():
                if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                    merged[key].update(value)
                elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
                    merged[key].extend(value)
                else:
                    merged[key] = value
        elif isinstance(config, list):
            if 'nodes' not in merged:
                merged['nodes'] = []
            merged['nodes'].extend(config)
    return merged

# 主函数
def main():
    # 创建 input 目录
    os.makedirs('input', exist_ok=True)

    # 获取并解析所有配置
    configs = fetch_and_parse_configs(urls)

    # 合并配置
    merged_config = merge_configs(configs)

    # 转换为 YAML
    yaml_output = yaml.dump(merged_config, allow_unicode=True, sort_keys=False)

    # 保存到 input/output.yml
    with open('input/output.yml', 'w', encoding='utf-8') as f:
        f.write(yaml_output)

    print("配置已合并并保存到 input/output.yml")
    print("\n合并后的 YAML 内容：")
    print(yaml_output)

if __name__ == "__main__":
    main()
