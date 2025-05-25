import requests
import subprocess
import time

# 直播源文件路径
TVLIST_FILE = "iptv_list.txt"
LOG_FILE = "stream_log.txt"

def read_stream_list(file_path):
    """读取直播源列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ 文件未找到: {file_path}")
        return []

def log_result(message):
    """记录结果到日志"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def check_stream_status(url):
    """检查直播源是否可用"""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            result = f"✅ 直播源可用: {url}"
        else:
            result = f"❌ 直播源不可用 (状态码: {response.status_code})"
    except requests.exceptions.RequestException:
        result = f"❌ 无法访问直播源: {url}"

    print(result)
    log_result(result)
    return result.startswith("✅")

def get_stream_info(url):
    """获取直播流的码率、分辨率、格式"""
    command = ["ffprobe", "-v", "error", "-select_streams", "v", "-show_entries",
               "stream=width,height,bit_rate,codec_name", "-of", "json", url]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        print(f"📊 直播流信息:\n{result.stdout}")
        log_result(f"📊 直播流信息 ({url}): {result.stdout}")
    except Exception as e:
        print(f"❌ 获取直播流信息失败: {e}")
        log_result(f"❌ 获取直播流信息失败 ({url}): {e}")

def measure_latency(url):
    """测量直播源的延迟"""
    start_time = time.time()
    try:
        requests.get(url, timeout=5)
        latency = time.time() - start_time
        result = f"⏳ 直播源延迟: {latency:.3f} 秒"
    except requests.exceptions.RequestException:
        result = "❌ 无法测量延迟"

    print(result)
    log_result(result)

def main():
    stream_list = read_stream_list(TVLIST_FILE)

    if not stream_list:
        print("⚠️ 未找到直播源，退出程序。")
        return

    print(f"📡 开始测试 {len(stream_list)} 个直播源...")
    log_result(f"📡 开始测试 {len(stream_list)} 个直播源...\n")

    for url in stream_list:
        print(f"\n🔎 测试直播源: {url}")
        if check_stream_status(url):
            get_stream_info(url)
            measure_latency(url)

    print("\n✅ 测试完成，日志已保存至 stream_log.txt")

if __name__ == "__main__":
    main()