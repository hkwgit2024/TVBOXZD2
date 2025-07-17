
import yaml
import base64
import logging

logger = logging.getLogger(__name__)

def load_config(config_file: str = "config.yaml") -> dict:
    """加载配置文件"""
    try:
        with open(config_file, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        config["banned_words"] = base64.b64decode(config["banned_words"]).decode('utf-8').split()
        return config
    except Exception as e:
        logger.error(f"加载配置文件失败：{e}")
        raise

config = load_config()
