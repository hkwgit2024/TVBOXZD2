import yaml
import logging
import json

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(file_path="config/config.yaml"):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            logging.debug(f"加载的配置：\n{json.dumps(config, indent=2, ensure_ascii=False)}")
            return config
    except yaml.YAMLError as e:
        logging.error(f"YAML 解析错误：{e}")
        return None
    except Exception as e:
        logging.error(f"加载配置文件错误：{e}")
        return None

def filter_and_modify_channels(channels, config):
    filtered_channels = []
    for name, url in channels:
        original_name = name
        for old_str, new_str in config.get('channel_name_replacements', {}).items():
            name = name.replace(old_str, new_str)
            if name != original_name:
                logging.debug(f"频道名称从 '{original_name}' 替换为 '{name}'")
        filtered_channels.append((name, url))
    return filtered_channels

# 测试代码
config = load_config()
if config:
    test_channels = [
        ("CCTV01", "http://example.com/cctv1"),
        ("TVB翡翠（）", "http://example.com/tvb"),
        ("东森新闻", "http://example.com/dongsen")
    ]
    result = filter_and_modify_channels(test_channels, config)
    for name, url in result.:

        print(f"{name},{url}")
