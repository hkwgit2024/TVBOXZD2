import os
import yaml
import subprocess
import re
import json
import time
from datetime import datetime

# 文件路径
CONFIG_DIR = 'config'
OUTPUT_DIR = 'output'
SCRIPTS_DIR = 'scripts' # 新增脚本目录变量

URLS_FILE = os.path.join(CONFIG_DIR, 'urls.txt')
CONFIG_FILE = os.path.join(SCRIPTS_DIR, 'config.yaml') # <--- 路径已更新
LIST_FILE = os.path.join(OUTPUT_DIR, 'list.txt')
MPEG_FILE = os.path.join(OUTPUT_DIR, 'mpeg.txt')
FAILED_FILE = os.path.join(OUTPUT_DIR, 'failed.txt')
STATUS_FILE = os.path.join(OUTPUT_DIR, 'status.json')

# 确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_config():
    """加载配置文件"""
    if not os.path.exists(CONFIG_FILE):
        print(f"错误：配置文件 {CONFIG_FILE} 不存在。")
        exit(1)
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def load_urls():
    """加载urls.txt中的URL，去除注释和空行"""
    urls = set()
    if not os.path.exists(URLS_FILE):
        return urls
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.add(line.split('#')[0].strip()) # 去除行内注释
    return sorted(list(urls)) # 返回排序后的列表，便于一致性

def load_previous_status():
    """加载上次运行的状态（时间戳和失败列表）"""
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"last_urls_modified_time": 0, "failed_urls": []}
    return {"last_urls_modified_time": 0, "failed_urls": []}

def save_current_status(last_modified_time, failed_urls):
    """保存当前运行的状态"""
    with open(STATUS_FILE, 'w', encoding='utf-8') as f:
        json.dump({"last_urls_modified_time": last_modified_time, "failed_urls": failed_urls}, f, indent=4)

def get_file_modified_time(filepath):
    """获取文件的修改时间戳"""
    if os.path.exists(filepath):
        return os.path.getmtime(filepath)
    return 0

def write_to_file(filepath, content, mode='w'):
    """写入内容到文件"""
    with open(filepath, mode, encoding='utf-8') as f:
        if isinstance(content, list):
            for item in content:
                f.write(item + '\n')
        else:
            f.write(content + '\n')

def get_ffmpeg_params(url, config):
    """根据URL协议获取FFmpeg参数"""
    protocol = url.split('://')[0] if '://' in url else 'default'
    
    global_params = config.get('ffmpeg_global_params', '').split()
    
    proto_config = config['protocols'].get(protocol, config['protocols']['default'])
    
    timeout_ms = proto_config.get('timeout', config['protocols']['default']['timeout']) * 1_000_000 # 转换为微秒
    retries = proto_config.get('retries', config['protocols']['default']['retries'])
    max_duration_check = proto_config.get('max_duration_check', config['protocols']['default']['max_duration_check'])
    extra_params = proto_config.get('extra_params', config['protocols']['default']['extra_params']).split()
    
    # 结合参数
    params = global_params + [
        '-timeout', str(timeout_ms),
        '-t', str(max_duration_check),
        '-i', url,
        '-vn', '-an', '-sn', # 禁用视频、音频、字幕录制
        '-f', 'null', # 输出到空设备
    ] + extra_params
    
    return params, retries

def check_stream(url, config):
    """
    使用FFmpeg检测节目源是否可用
    返回 (是否成功, 错误信息/流信息)
    """
    ffmpeg_cmd, retries = get_ffmpeg_params(url, config)
    
    for attempt in range(retries):
        print(f"正在检测: {url} (尝试 {attempt + 1}/{retries})")
        try:
            # 使用 stderr 获取 FFmpeg 的日志输出，包括错误信息
            process = subprocess.run(ffmpeg_cmd, capture_output=True, text=True, timeout=config['protocols']['default']['timeout'] + 5) # 加上5秒buffer防止FFmpeg卡住
            
            # FFmpeg 返回码 0 表示成功
            if process.returncode == 0:
                # 检查stderr中是否有 "No such file or directory" 或者 "Protocol not found" 等关键错误信息
                # 即使返回码为0，也可能因为流太短或内容不符合预期而实际上不可用
                if "Could not open" in process.stderr or "Protocol not found" in process.stderr:
                     return False, f"FFmpeg 报告错误: {process.stderr.strip()}"
                print(f"成功检测: {url}")
                return True, process.stderr # FFmpeg 的流信息通常在 stderr
            else:
                error_message = process.stderr.strip()
                print(f"FFmpeg 检测失败: {url}, 错误: {error_message}")
                return False, error_message
        except subprocess.TimeoutExpired:
            print(f"检测超时: {url}")
            return False, "检测超时"
        except FileNotFoundError:
            return False, "FFmpeg 命令未找到。请确保FFmpeg已安装并添加到PATH中。"
        except Exception as e:
            print(f"发生未知错误: {url}, 错误: {e}")
            return False, str(e)
            
    return False, f"所有 {retries} 次尝试均失败"

def classify_stream(url, stream_info):
    """
    简单分类节目源，目前根据URL关键词和FFmpeg输出信息进行分类。
    可以根据需求扩展分类逻辑。
    """
    category = "未知"
    
    # 基于URL关键词分类
    if "cctv" in url.lower():
        category = "央视"
    elif "btv" in url.lower() or "beijing" in url.lower():
        category = "北京卫视"
    elif "hunan" in url.lower() or "芒果" in url.lower():
        category = "湖南卫视"
    elif "m3u8" in url.lower():
        category = "HLS流"
    elif "rtmp" in url.lower():
        category = "RTMP流"
        
    # 基于FFmpeg输出信息（示例：解析分辨率）
    # 这一步需要解析 stream_info，这通常在 stderr 中
    resolution_match = re.search(r'Stream #.*: Video:.*, (\d{3,4}x\d{3,4})', stream_info)
    if resolution_match:
        resolution = resolution_match.group(1)
        category += f" ({resolution})"
        
    return category

def main():
    config = load_config()
    
    # 加载上次运行的状态
    status = load_previous_status()
    last_urls_modified_time = status.get("last_urls_modified_time", 0)
    previous_failed_urls = set(status.get("failed_urls", []))
    
    current_urls_modified_time = get_file_modified_time(URLS_FILE)
    
    all_urls = load_urls()
    
    # 检查urls.txt是否更新
    if current_urls_modified_time <= last_urls_modified_time and all_urls:
        print(f"urls.txt 未更新 (上次修改时间: {datetime.fromtimestamp(last_urls_modified_time)}), 跳过完整检测。")
        print("请手动删除output/status.json来强制重新检测所有URL。")
        return
        
    print(f"urls.txt 已更新或首次运行 (当前修改时间: {datetime.fromtimestamp(current_urls_modified_time)}), 进行检测。")

    # 去重并写入list.txt
    write_to_file(LIST_FILE, all_urls)
    print(f"去重后的URL已保存到 {LIST_FILE}, 共 {len(all_urls)} 条。")

    successful_urls = []
    current_failed_urls = []
    
    # 用于分类的字典
    categorized_urls = {}

    for url in all_urls:
        if url in previous_failed_urls:
            print(f"跳过上次检测失败的URL: {url}")
            current_failed_urls.append(url) # 仍然添加到当前失败列表，以便更新状态
            continue
            
        success, info = check_stream(url, config)
        if success:
            successful_urls.append(url)
            category = classify_stream(url, info)
            if category not in categorized_urls:
                categorized_urls[category] = []
            categorized_urls[category].append(url)
        else:
            current_failed_urls.append(url + f" # 失败原因: {info}")

    # 保存检测结果
    write_to_file(MPEG_FILE, successful_urls)
    print(f"可用节目源已保存到 {MPEG_FILE}, 共 {len(successful_urls)} 条。")
    
    write_to_file(FAILED_FILE, current_failed_urls)
    print(f"失败节目源已保存到 {FAILED_FILE}, 共 {len(current_failed_urls)} 条。")

    # 保存分类结果
    for category, urls in categorized_urls.items():
        # 清理文件名中的非法字符
        safe_category_name = re.sub(r'[\\/:*?"<>| ]', '_', category)
        category_file = os.path.join(OUTPUT_DIR, f"{safe_category_name}.txt")
        write_to_file(category_file, urls)
        print(f"分类 '{category}' 的节目源已保存到 {category_file}, 共 {len(urls)} 条。")
    
    # 更新状态文件
    save_current_status(current_urls_modified_time, [item.split(' #')[0] for item in current_failed_urls]) # 只保存URL，不带失败原因

if __name__ == "__main__":
    main()
