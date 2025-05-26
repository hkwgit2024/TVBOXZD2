import requests
import subprocess
import time
import os
import json # 导入 json 模块，用于解析 ffprobe 的输出

# 直播源文件路径
TVLIST_FILE = "iptv_list.txt"
LOG_FILE = "stream_log.txt"
SUCCESS_FILE = "successful_streams.txt" # 新增：成功直播源文件

def read_stream_list(file_path):
    """
    读取直播源列表，从 '频道名称,URL' 格式中提取 URL
    同时跳过非标准格式的行，如标题行。
    """
    urls = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: # 跳过空行
                    continue
                
                # 尝试按第一个逗号分割行
                parts = line.split(',', 1) 
                
                # 检查是否成功分割成两部分，并且第二部分看起来像一个URL
                if len(parts) == 2 and (parts[1].startswith("http://") or parts[1].startswith("https://")):
                    urls.append(parts[1])
                else:
                    # 记录那些无法识别的行，有助于调试
                    print(f"⚠️ 忽略非标准格式行（或头部信息）: {line}")
                    log_result(f"⚠️ 忽略非标准格式行（或头部信息）: {line}")
            return urls
    except FileNotFoundError:
        print(f"❌ 文件未找到: {file_path}")
        return []

def log_result(message):
    """记录结果到日志"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def log_successful_stream(url):
    """记录成功的直播源到单独的文件"""
    with open(SUCCESS_FILE, "a", encoding="utf-8") as f:
        f.write(url + "\n")

def check_stream_status(url):
    """检查直播源是否可用"""
    try:
        # 增加 headers 模拟浏览器请求，有时可以提高成功率
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        # stream=True 避免一次性下载整个流，timeout 设置为5秒
        response = requests.get(url, timeout=5, headers=headers, stream=True)
        if response.status_code == 200:
            result = f"✅ 直播源可用: {url}"
            print(result)
            log_result(result)
            log_successful_stream(url) # 在这里调用，表示流可用
            return True
        else:
            result = f"❌ 直播源不可用 (状态码: {response.status_code}) - {url}"
            print(result)
            log_result(result)
            return False
    except requests.exceptions.Timeout:
        result = f"❌ 访问直播源超时 (5秒): {url}"
        print(result)
        log_result(result)
        return False
    except requests.exceptions.ConnectionError:
        result = f"❌ 无法建立连接（DNS错误或拒绝连接）: {url}"
        print(result)
        log_result(result)
        return False
    except requests.exceptions.RequestException as e:
        result = f"❌ 无法访问直播源 (未知错误: {e}): {url}"
        print(result)
        log_result(result)
        return False

def get_stream_info(url):
    """获取直播流的码率、分辨率、格式"""
    # 确保 ffprobe 已安装并配置在 PATH 中
    command = ["ffprobe", "-v", "error", "-print_format", "json", "-show_streams", url]
    process = None # 初始化 process 变量
    try:
        # 使用 Popen 来获取更多进程控制权
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # communicate() 方法会等待子进程结束，并捕获其 stdout 和 stderr
        # 增加超时时间，以应对 ffprobe 可能卡住的情况
        stdout, stderr = process.communicate(timeout=15) # 15秒超时

        if process.returncode == 0:
            try:
                # 尝试解析 ffprobe 的 JSON 输出
                info = json.loads(stdout)
                # 你可以在这里进一步解析 'info' 来提取码率、分辨率、格式等具体信息
                print(f"📊 直播流信息 ({url}):\n{json.dumps(info, indent=2)}")
                log_result(f"📊 直播流信息 ({url}): {stdout}")
            except json.JSONDecodeError:
                print(f"❌ ffprobe 输出不是有效的JSON ({url}): {stdout}")
                log_result(f"❌ ffprobe 输出不是有效的JSON ({url}): {stdout}")
        else:
            print(f"❌ ffprobe 执行失败 ({url}): {stderr}")
            log_result(f"❌ ffprobe 执行失败 ({url}): {stderr}")
    except FileNotFoundError:
        print(f"❌ ffprobe 未找到。请确保已安装 FFmpeg 且 ffprobe 在系统 PATH 中。")
        log_result(f"❌ ffprobe 未找到。请确保已安装 FFmpeg 且 ffprobe 在系统 PATH 中。")
    except subprocess.TimeoutExpired:
        # 如果 ffprobe 超时，确保终止该进程
        if process:
            process.kill()
            # 再次调用 communicate() 来清理管道并确保进程完全终止
            stdout, stderr = process.communicate()
        print(f"❌ ffprobe 获取信息超时 ({url})")
        log_result(f"❌ ffprobe 获取信息超时 ({url})")
    except Exception as e:
        print(f"❌ 获取直播流信息时发生未知错误: {e} ({url})")
        log_result(f"❌ 获取直播流信息时发生未知错误: {e} ({url})")
    finally:
        # 确保 ffprobe 进程无论如何都已终止
        if process and process.poll() is None: # 如果进程仍在运行
            process.kill()

def measure_latency(url):
    """测量直播源的延迟 (仅测量连接时间)"""
    start_time = time.time()
    try:
        # 使用 HEAD 请求通常更快，因为不需要下载内容
        requests.head(url, timeout=5)
        latency = time.time() - start_time
        result = f"⏳ 直播源延迟: {latency:.3f} 秒 - {url}"
    except requests.exceptions.RequestException:
        result = f"❌ 无法测量延迟: {url}"

    print(result)
    log_result(result)

def main():
    # 清空之前的成功文件内容和日志文件内容，以便每次运行都是最新的
    # 检查文件是否存在，如果不存在则创建，存在则清空
    for f_path in [SUCCESS_FILE, LOG_FILE]:
        if os.path.exists(f_path):
            open(f_path, 'w', encoding='utf-8').close()
        else:
            # 文件不存在时，简单地创建一个空文件
            with open(f_path, 'w', encoding='utf-8') as f:
                pass

    stream_list = read_stream_list(TVLIST_FILE)

    if not stream_list:
        print("⚠️ 未找到有效直播源，请检查 iptv_list.txt 文件格式。退出程序。")
        return

    print(f"📡 开始测试 {len(stream_list)} 个直播源...")
    log_result(f"📡 开始测试 {len(stream_list)} 个直播源...\n")

    for url in stream_list:
        print(f"\n🔎 测试直播源: {url}")
        # 在执行每个检查之前打印 DEBUG 信息，以帮助定位卡顿点
        print(f"DEBUG: 正在检查状态: {url}")
        if check_stream_status(url):
            print(f"DEBUG: 状态检查通过，正在获取流信息: {url}")
            # 只有当 check_stream_status 成功时才尝试获取 ffprobe 信息和测量延迟
            get_stream_info(url)
            print(f"DEBUG: 流信息获取完成，正在测量延迟: {url}")
            measure_latency(url)
            print(f"DEBUG: 延迟测量完成: {url}")
        else:
            print(f"DEBUG: 状态检查失败，跳过信息和延迟测量: {url}")
        time.sleep(0.5) # 稍微暂停一下，避免请求过快被服务器拒绝

    print(f"\n✅ 测试完成，详细日志已保存至 {LOG_FILE}，成功直播源已保存至 {SUCCESS_FILE}")

if __name__ == "__main__":
    main()
