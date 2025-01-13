class ServiceMapper:
    WELL_KNOWN_PORTS = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        25: 'SMTP',
        53: 'DNS',
        # Add more ports as needed
    }
    
    def get_service(self, port):
        return self.WELL_KNOWN_PORTS.get(port, 'Unknown')
