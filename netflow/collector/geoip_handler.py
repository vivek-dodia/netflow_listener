# collector/geoip_handler.py

import geoip2.database
import os

class GeoIPHandler:
    def __init__(self, geoip_db='geoip/GeoLite2-City.mmdb'):
        self.geoip_reader = None
        if os.path.exists(geoip_db):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db)
                print(f"Loaded GeoIP database from {geoip_db}")
            except Exception as e:
                print(f"Error loading GeoIP database: {e}")
        else:
            print(f"Warning: GeoIP database not found at {geoip_db}")
    
    def get_location_info(self, ip):
        """Get GeoIP information for an IP address."""
        result = {
            'country': 'unknown',
            'asn': 'unknown'
        }
        
        if self.geoip_reader and ip != 'unknown':
            try:
                location = self.geoip_reader.city(ip)
                result['country'] = location.country.iso_code if location.country else 'unknown'
                result['asn'] = str(location.traits.autonomous_system_number) if location.traits.autonomous_system_number else 'unknown'
            except Exception as e:
                print(f"GeoIP lookup failed for {ip}: {e}")
                
        return result
    
    def close(self):
        """Close the GeoIP database reader."""
        try:
            if self.geoip_reader:
                self.geoip_reader.close()
        except Exception as e:
            print(f"Error closing GeoIP database: {e}")
            
    def __del__(self):
        """Ensure the database is closed on object destruction."""
        self.close()
