class GeoIPHandler:
    def __init__(self, geoip_db=None):
        self.geoip_reader = None
        if geoip_db:
            try:
                import geoip2.database
                self.geoip_reader = geoip2.database.Reader(geoip_db)
            except ImportError:
                print("Warning: geoip2 package not available. GeoIP lookups disabled.")
                
    def get_location(self, ip_address):
        if not self.geoip_reader:
            return None
            
        try:
            return self.geoip_reader.city(ip_address)
        except Exception:
            return None
