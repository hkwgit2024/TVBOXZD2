import yaml
import base64
import logging

logger = logging.getLogger(__name__)

def load_config(config_file: str = "config.yaml") -> dict:
    """
    加载配置文件 config.yaml。
    Args:
        config_file: 配置文件路径，默认为 'config.yaml'。
    Returns:
        dict: 解析后的配置字典。
    Raises:
        FileNotFoundError: 如果配置文件不存在。
        yaml.YAMLError: 如果 YAML 解析失败。
    """
    try:
        with open(config_file, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        config["banned_words"] = base64.b64decode(config["banned_words"]).decode('utf-8').split()
        return config
    except FileNotFoundError:
        logger.error(f"配置文件 {config_file} 不存在")
        raise
    except yaml.YAMLError as e:
        logger.error(f"解析配置文件 {config_file} 失败：{e}")
        raise
    except Exception as e:
        logger.error(f"加载配置文件 {config_file} 时发生未知错误：{e}")
        raise

config = load_config()
