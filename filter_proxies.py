import yaml
import requests
import socket
import json
import os

# 缓存文件路径
CACHE_FILE = 'ip_cache.json'

def load_cache():
    """从文件中加载缓存数据。"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"警告: 无法加载缓存文件，将创建新的缓存。错误: {e}")
    return {}

def save_cache(cache):
    """将缓存数据保存到文件。"""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)

def resolve_domains(hosts, cache):
    """
    解析域名为IP地址，并从缓存中获取已有的IP。
    """
    ips_to_query = []
    host_to_ip_map = {}
    
    for host in hosts:
        # 尝试从缓存中获取IP地址
        cached_ip = cache.get(host)
        if cached_ip:
            host_to_ip_map[host] = cached_ip
            continue

        try:
            ip_address = socket.gethostbyname(host)
            host_to_ip_map[host] = ip_address
            # 将新的解析结果添加到缓存中
            cache[host] = ip_address
            
            # 如果IP地址不在缓存中，则加入待查询列表
            if ip_address not in cache:
                ips_to_query.append(ip_address)
        except socket.gaierror:
            print(f"警告: 无法解析域名: {host}")
    return host_to_ip_map, ips_to_query

def get_country_codes_batch(ips):
    """
    使用ip-api.com的批量接口查询IP地址的国家代码。
    """
    if not ips:
        return {}

    print(f"正在使用批量查询接口查询 {len(ips)} 个IP...")
    
    # 将IP列表分割成每批最多100个
    chunk_size = 100
    results = {}
    
    for i in range(0, len(ips), chunk_size):
        ip_chunk = ips[i:i + chunk_size]
        try:
            response = requests.post('http://ip-api.com/batch', json=ip_chunk, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for item in data:
                if item['status'] == 'success':
                    results[item['query']] = item['countryCode']
        except Exception as e:
            print(f"批量查询失败: {e}")
            return {}
            
    return results

def main():
    """
    主函数，用于下载、筛选和保存Clash配置。
    """
    # 加载缓存
    cache = load_cache()
    
    include_codes = {'JP', 'KR', 'HK', 'TW', 'SG', 'MY', 'PH', 'VN', 'TH', 'LA', 'MM', 'RU', 'MN'}
    config_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash_config.yaml'
    
    print("开始下载配置文件...")
    try:
        response = requests.get(config_url)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
        print("配置文件下载并解析成功。")
    except Exception as e:
        print(f"下载或解析配置文件失败: {e}")
        return
    
    if 'proxies' not in config:
        print('配置中没有找到 proxies 列表。')
        return

    hosts = [proxy.get('server') for proxy in config['proxies'] if proxy.get('server')]
    print(f"配置文件中共有 {len(hosts)} 个代理服务器。")

    # 解析域名并获取需要查询的IP列表
    host_to_ip_map, ips_to_query = resolve_domains(hosts, cache)
    
    # 执行批量查询
    ip_to_country_map = get_country_codes_batch(ips_to_query)
    
    # 将批量查询结果和缓存中的IP信息合并到缓存中
    for ip, country_code in ip_to_country_map.items():
        cache[ip] = country_code
    
    # 筛选节点
    filtered_proxies = []
    for proxy in config['proxies']:
        host = proxy.get('server')
        if not host:
            continue
        
        ip_address = host_to_ip_map.get(host)
        if ip_address:
            country_code = cache.get(ip_address)
            if country_code and country_code in include_codes:
                filtered_proxies.append(proxy)
    
    config['proxies'] = filtered_proxies
    
    with open('filtered_by_ip.yaml', 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    
    print(f"已成功筛选出 {len(filtered_proxies)} 个节点，并保存到 filtered_by_ip.yaml。")
    
    # 保存更新后的缓存
    save_cache(cache)

if __name__ == '__main__':
    main()
