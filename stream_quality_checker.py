
import os
import json
import logging
import logging.handlers
import subprocess
import re
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置日志系统
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转"""
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.handlers = [file_handler, console_handler]
    return logger

# 全局配置
CONFIG = load_config()
setup_logging(CONFIG)

# 性能监控装饰器
def performance_monitor(func):
    """记录函数执行时间的装饰器"""
    if not CONFIG['performance_monitor']['enabled']:
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

# 读取频道列表
@performance_monitor
def read_channels(file_path):
    """从文件读取频道列表，跳过无效条目"""
    channels = []
    invalid_patterns = CONFIG.get('url_pre_screening', {}).get('invalid_url_patterns', [])
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#') or '#genre#' in line:
                    continue
                if ',' not in line:
                    logging.info(f"跳过无效行: {line}")
                    continue
                name, url = line.split(',', 1)
                name = name.strip()
                url = url.strip()
                if any(re.search(pattern, url, re.IGNORECASE) for pattern in invalid_patterns):
                    logging.info(f"跳过无效 URL: {name} ({url})")
                    continue
                if not url.startswith(('http://', 'https://', 'rtmp://', 'rtp://')):
                    logging.info(f"跳过非流媒体协议: {name} ({url})")
                    continue
                channels.append((name, url))
        logging.info(f"从 '{file_path}' 读取 {len(channels)} 个有效频道")
        return channels
    except FileNotFoundError:
        logging.error(f"文件 '{file_path}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_path}' 失败: {e}")
        return []

# 检查视频流质量
@performance_monitor
def check_stream_quality(channel_name, url, timeout=CONFIG['stream_quality']['max_check_duration']):
    """使用 ffprobe 检查视频流的播放效果"""
    # 预检查 URL
    try:
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.head(url, timeout=10, allow_redirects=True)
        content_type = response.headers.get('content-type', '').lower()
        valid_types = ('video/', 'application/vnd.apple.mpegurl', 'application/octet-stream')
        if not any(t in content_type for t in valid_types):
            logging.info(f"频道 {channel_name} ({url}) 不是有效的流媒体类型: {content_type}")
            return False, f"无效的流媒体类型 ({content_type})"
    except requests.RequestException as e:
        logging.info(f"频道 {channel_name} ({url}) 无法访问: {str(e)}")
        return False, f"无法访问 ({str(e)})"

    try:
        # 检查 ffprobe
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.error("ffprobe 未找到或不可用，跳过流质量检查")
        return False, "ffprobe 不可用"

    # ffprobe 检查流信息
    max_retries = 2
    for attempt in range(max_retries):
        try:
            cmd = [
                'ffprobe',
                '-v', 'error',
                '-show_streams',
                '-show_format',
                '-print_format', 'json',
                '-timeout', str(int(timeout * 1000000)),
                url
            ]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True
            )
            break
        except subprocess.TimeoutExpired:
            if attempt == max_retries - 1:
                logging.info(f"频道 {channel_name} ({url}) 检查超时")
                return False, "检查超时"
            logging.info(f"频道 {channel_name} ({url}) 第 {attempt + 1} 次尝试超时，重试...")
            time.sleep(1)

    try:
        stream_info = json.loads(result.stdout)
        video_stream = None
        for stream in stream_info.get('streams', []):
            if stream.get('codec_type') == 'video':
                video_stream = stream
                break
        
        if not video_stream:
            logging.info(f"频道 {channel_name} ({url}) 无视频流")
            return False, "无视频流"

        # 检查分辨率
        width = video_stream.get('width', 0)
        height = video_stream.get('height', 0)
        if width < CONFIG['stream_quality']['min_resolution_width'] or height < CONFIG['stream_quality']['min_resolution_height']:
            logging.info(f"频道 {channel_name} ({url}) 分辨率过低: {width}x{height}")
            return False, f"分辨率过低 ({width}x{height})"

        # 检查比特率
        bitrate = int(stream_info.get('format', {}).get('bit_rate', 0))
        if bitrate != 0 and bitrate < CONFIG['stream_quality']['min_bitrate']:
            if width >= 1280 and height >= 720:
                logging.info(f"频道 {channel_name} ({url}) 比特率低但分辨率高，允许通过")
            else:
                logging.info(f"频道 {channel_name} ({url}) 比特率过低: {bitrate} bps")
                return False, f"比特率过低 ({bitrate} bps)"

        # 检查初始缓冲时间
        start_time = float(stream_info.get('format', {}).get('start_time', 0))
        if start_time > CONFIG['stream_quality']['max_buffer_time'] and start_time < 3600:
            logging.info(f"频道 {channel_name} ({url}) 初始缓冲时间过长: {start_time} 秒")
            return False, f"初始缓冲时间过长 ({start_time} 秒)"

        # 检查关键帧间隔
        frame_cmd = [
            'ffprobe',
            '-v', 'error',
            '-show_frames',
            '-print_format', 'json',
            '-read_intervals', f"%+{CONFIG['stream_quality']['max_check_duration']}",
            url
        ]
        frame_result = subprocess.run(
            frame_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True
        )
        frame_info = json.loads(frame_result.stdout)
        keyframe_intervals = []
        last_keyframe_time = 0
        for frame in frame_info.get('frames', []):
            if frame.get('key_frame') == 1:
                frame_time = float(frame.get('best_effort_timestamp_time', 0))
                if last_keyframe_time:
                    interval = frame_time - last_keyframe_time
                    keyframe_intervals.append(interval)
                last_keyframe_time = frame_time

        if keyframe_intervals:
            avg_keyframe_interval = sum(keyframe_intervals) / len(keyframe_intervals)
            if avg_keyframe_interval > CONFIG['stream_quality']['max_keyframe_interval']:
                logging.info(f"频道 {channel_name} ({url}) 关键帧间隔过大: {avg_keyframe_interval} 秒")
                return False, f"关键帧间隔过大 ({avg_keyframe_interval} 秒)"

        # 检查广告关键字
        format_tags = stream_info.get('format', {}).get('tags', {})
        for key, value in format_tags.items():
            if any(ad_keyword.lower() in str(value).lower() for ad_keyword in CONFIG['stream_quality']['ad_keywords']):
                logging.info(f"频道 {channel_name} ({url}) 检测到广告关键字: {key}={value}")
                return False, f"检测到广告 ({key}={value})"

        logging.info(f"频道 {channel_name} ({url}) 通过质量检查，分辨率: {width}x{height}, 比特率: {bitrate} bps")
        return True, None
    except subprocess.TimeoutExpired:
        logging.info(f"频道 {channel_name} ({url}) 检查超时")
        return False, "检查超时"
    except json.JSONDecodeError:
        logging.info(f"频道 {channel_name} ({url}) ffprobe 输出解析失败")
        return False, "ffprobe 输出解析失败"
    except Exception as e:
        logging.info(f"频道 {channel_name} ({url}) 检查失败: {e}")
        return False, f"检查失败 ({str(e)})"

# 多线程检查频道
@performance_monitor
def check_channels_multithreaded(channels, max_workers=CONFIG['stream_quality']['stream_check_workers']):
    """多线程检查频道播放效果"""
    valid_channels = []
    total_channels = len(channels)
    logging.warning(f"开始多线程检查 {total_channels} 个频道的播放效果")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_stream_quality, name, url): (name, url) for name, url in channels}
        for i, future in enumerate(as_completed(futures)):
            name, url = futures[future]
            if (i + 1) % CONFIG['performance_monitor']['log_interval'] == 0:
                logging.warning(f"已检查 {i + 1}/{total_channels} 个频道")
            try:
                is_valid, error = future.result()
                if is_valid:
                    valid_channels.append((name, url))
                else:
                    logging.info(f"频道 {name} ({url}) 未通过检查: {error}")
            except Exception as e:
                logging.error(f"检查频道 {name} ({url}) 时发生异常: {e}")
    
    logging.warning(f"完成播放效果检查，{len(valid_channels)}/{total_channels} 个频道通过")
    return valid_channels

# 写入高质量频道列表
@performance_monitor
def write_high_quality_channels(file_path, channels):
    """将高质量频道写入文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write("高质量频道,#genre#\n")
            for name, url in sorted(channels, key=lambda x: x[0]):
                file.write(f"{name},{url}\n")
        logging.info(f"写入 {len(channels)} 个高质量频道到 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# 主函数
@performance_monitor
def main():
    """主函数，执行频道播放效果检查流程"""
    logging.warning("开始执行频道播放效果检查")
    total_start_time = time.time()

    input_file = "output/iptv_list.txt"
    channels = read_channels(input_file)
    if not channels:
        logging.error(f"未从 '{input_file}' 读取到有效频道，退出")
        exit(1)

    valid_channels = check_channels_multithreaded(channels)
    output_file = CONFIG['output']['paths']['high_quality_iptv_file']
    write_high_quality_channels(output_file, valid_channels)

    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"频道播放效果检查完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
