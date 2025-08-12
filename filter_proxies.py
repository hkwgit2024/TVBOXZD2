import yaml
import requests
import socket
import os
import sys

# 尝试导入 geoip2 库，如果失败则给出安装提示
try:
    import geoip2.database
except ImportError:
    print("错误: 未找到 geoip2 库。请在你的GitHub Actions工作流中添加安装步骤:", file=sys.stderr)
    print("pip install geoip2", file=sys.stderr)
    sys.exit(1)

# GeoLite2 数据库文件路径
DATABASE_FILE = 'GeoLite2-Country.mmdb'
# 缓存文件路径
CACHE_FILE = 'ip_cache.json'

def get_country_code_from_local_db(ip_address):
    """
    使用本地GeoLite2数据库查询IP地址的国家代码。
    """
    if not os.path.exists(DATABASE_FILE):
        print(f"错误: 未找到数据库文件 '{DATABASE_FILE}'。请下载并上传到仓库根目录。", file=sys.stderr)
        return None
    
    try:
        with geoip2.database.Reader(DATABASE_FILE) as reader:
            response = reader.country(ip_address)
            return response.country.iso_code
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception as e:
        print(f"查询IP {ip_address} 时发生错误: {e}", file=sys.stderr)
        return None

def main():
    """
    主函数，用于下载、筛选和保存Clash配置。
    """
    include_codes = {'JP', 'KR', 'HK', 'TW', 'SG', 'MY', 'PH', 'VN', 'TH', 'LA', 'MM', 'RU', 'MN', 'CA', 'US'}
    config_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash_config.yaml'
    
    print("开始下载配置文件...")
    try:
        response = requests.get(config_url)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
        print("配置文件下载并解析成功。")
    except Exception as e:
        print(f"下载或解析配置文件失败: {e}", file=sys.stderr)
        return
    
    if 'proxies' not in config:
        print('配置中没有找到 proxies 列表。', file=sys.stderr)
        return

    filtered_proxies = []
    print(f"配置文件中共有 {len(config['proxies'])} 个代理。")
    
    for proxy in config['proxies']:
        host = proxy.get('server')
        if not host:
            continue
        
        try:
            # 解析域名为IP地址
            ip_address = socket.gethostbyname(host)
            country_code = get_country_code_from_local_db(ip_address)
            
            if country_code and country_code in include_codes:
                filtered_proxies.append(proxy)
                print(f"✅ 节点 {proxy.get('name', host)} (IP: {ip_address}) 匹配国家代码 {country_code}，已保留。")
            else:
                print(f"❌ 节点 {proxy.get('name', host)} (IP: {ip_address}) 不匹配国家代码 {country_code if country_code else '未知'}，已过滤。")
                
        except socket.gaierror:
            print(f"警告: 无法解析域名: {host}", file=sys.stderr)
            continue
    
    config['proxies'] = filtered_proxies
    
    with open('filtered_by_ip.yaml', 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    
    print(f"已成功筛选出 {len(filtered_proxies)} 个节点，并保存到 filtered_by_ip.yaml。")

if __name__ == '__main__':
    main()
