import geoip2.database

class GeoLite2Country:
    def __init__(self, db_path):
        self.db_path = db_path
        self.reader = None
        self.connect()

    def connect(self):
        try:
            self.reader = geoip2.database.Reader(self.db_path)
        except FileNotFoundError:
            raise

    def get_location(self, ip_address):
        """获取 IP 的国家信息"""
        try:
            response = self.reader.country(ip_address)
            country_name = response.country.names.get('zh-CN', response.country.name)
            country_code = response.country.iso_code
            return country_code, country_name
        except geoip2.errors.AddressNotFoundError:
            return None, "未知"
        except Exception as e:
            print(f"查询地理位置时发生错误: {e}")
            return None, "未知"
