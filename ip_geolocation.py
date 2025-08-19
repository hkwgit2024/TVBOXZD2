import geoip2.database

class GeoLite2Country:
    def __init__(self, db_path):
        self.db_path = db_path
        self.reader = None

    def __enter__(self):
        self.reader = geoip2.database.Reader(self.db_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.reader:
            self.reader.close()

    def get_country_by_ip(self, ip_address):
        try:
            response = self.reader.country(ip_address)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception:
            return "Error"
