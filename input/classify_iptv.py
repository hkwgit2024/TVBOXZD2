import re
import requests
from collections import defaultdict
from datetime import datetime
from urllib.parse import quote
import time
import json
import os

def search_channel_category(channel_name):
    """通过在线搜索获取频道分类"""
    try:
        # 使用简单的搜索API（这里以示例API替代，实际使用时需替换为可靠的搜索服务）
        search_url = f"https://api.duckduckgo.com/?q={quote(channel_name + ' 电视频道 类型')}&format=json"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
        response = requests.get(search_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            abstract = data.get('Abstract', '').lower()
            related = ' '.join([topic.get('Text', '') for topic in data.get('RelatedTopics', [])]).lower()
            content = abstract + ' ' + related

            # 分类关键词匹配
            if any(word in content for word in ['新闻', 'news']):
                return '新闻'
            elif any(word in content for word in ['电影', 'movie', 'film']):
                return '电影'
            elif any(word in content for word in ['香港', 'hk', '凤凰', 'tvb', '有线', '明珠']):
                return '港澳台'
            elif any(word in content for word in ['剧', '连续剧', 'series', 'drama']):
                return '电视剧'
            elif any(word in content for word in ['体育', 'sport']):
                return '体育'
            elif any(word in content for word in ['音乐', 'music']):
                return '音乐'
            elif any(word in content for word in ['综艺', 'variety']):
                return '综艺'
            elif any(word in content for word in ['少儿', '儿童', 'kids', 'cartoon']):
                return '少儿'
            else:
                return '其他'
    except Exception as e:
        print(f"Search error for {channel_name}: {e}")
        return None

def load_cache(cache_file='category_cache.json'):
    """加载分类缓存"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache, cache_file='category_cache.json'):
    """保存分类缓存"""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Error saving cache: {e}")

def classify_iptv_sources(input_filepath, output_filepath):
    """
    读取 IPTV 节目源文件，进行分类，并输出到指定文件。
    优先使用在线搜索分类，备用使用名称规则分类。
    """
    classified_sources = defaultdict(list)
    update_time = ""
    cache = load_cache()
    new_cache = cache.copy()

    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                # 第一行是更新时间
                if i == 0:
                    update_time = line.split(',')[0]
                    continue

                # 第二行是 #genre#，跳过
                if i == 1 and line == '#genre#':
                    continue

                # 节目源行
                parts = line.split(',', 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    url = parts[1].strip()

                    # 首先检查缓存
                    category = cache.get(name)
                    if not category:
                        # 在线搜索分类
                        category = search_channel_category(name)
                        time.sleep(0.5)  # 防止请求过快

                        # 如果搜索失败，使用备用规则
                        if not category:
                            match = re.match(r'^(.*?)[_.,(（].*$', name)
                            if match:
                                category = match.group(1).strip()
                            elif '新闻' in name:
                                category = '新闻'
                            elif '电影' in name:
                                category = '电影'
                            elif any(kw in name for kw in ['香港', '无线', '有线', '凤凰', '明珠']):
                                category = '港澳台'
                            elif any(kw in name for kw in ['剧', '传', '记', '王', '宫', '部', '士', '侦', '探']):
                                category = '电视剧'
                            elif '体育' in name:
                                category = '体育'
                            elif '音乐' in name:
                                category = '音乐'
                            elif '综艺' in name:
                                category = '综艺'
                            elif any(kw in name for kw in ['少儿', '儿童']):
                                category = '少儿'
                            else:
                                category = '其他'

                        new_cache[name] = category

                    classified_sources[category].append(f"{name},{url}")
                else:
                    print(f"Warning: Skipping malformed line: {line}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_filepath}' not found.")
        return
    except Exception as e:
        print(f"An error occurred while reading the input file: {e}")
        return

    # 保存缓存
    save_cache(new_cache)

    # 获取当前日期作为更新时间，如果文件第一行没有提供
    if not update_time:
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 写入输出文件
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(f"{update_time},#genre#\n")
            for category in sorted(classified_sources.keys()):
                f.write(f"\n{category},#genre#\n")
                for entry in classified_sources[category]:
                    f.write(f"{entry}\n")
        print(f"Successfully classified IPTV sources to '{output_filepath}'.")
    except Exception as e:
        print(f"An error occurred while writing the output file: {e}")

if __name__ == '__main__':
    input_file = 'output/valid_iptv_sources.txt'
    output_file = 'input/list.txt'
    classify_iptv_sources(input_file, output_file)
