# utils/service_mapper.py

class ServiceMapper:
    # Define known service ports
    SERVICE_PORTS = {
        53: 'dns',
        80: 'http',
        443: 'https',
        22: 'ssh',
        8181: 'custom_web',
        25: 'smtp',
        123: 'ntp',
        67: 'dhcp',
        68: 'dhcp',
        161: 'snmp',
        162: 'snmp',
        389: 'ldap',
        636: 'ldaps',
        3306: 'mysql',
        5432: 'postgresql',
        27017: 'mongodb'
    }
    
    @staticmethod
    def categorize_service(record):
        """
        Categorize flow by service based on ports and protocol.
        Args:
            record: Flow record containing protocol, src_port, and dst_port
        Returns:
            str: Service category
        """
        try:
            src_port = record.get('src_port', 0)
            dst_port = record.get('dst_port', 0)
            protocol = record.get('protocol', 0)
            
            # Check both source and destination ports against known services
            for port in [src_port, dst_port]:
                if port in ServiceMapper.SERVICE_PORTS:
                    return ServiceMapper.SERVICE_PORTS[port]
            
            # Protocol-based categorization for non-standard ports
            if protocol == 1:  # ICMP
                return 'icmp'
            elif protocol == 6:  # TCP
                # Common ephemeral port ranges
                if dst_port >= 32768 and dst_port <= 65535:
                    return 'tcp_ephemeral'
                return 'tcp_other'
            elif protocol == 17:  # UDP
                if dst_port >= 32768 and dst_port <= 65535:
                    return 'udp_ephemeral'
                return 'udp_other'
            elif protocol == 47:  # GRE
                return 'gre'
            elif protocol == 50:  # ESP
                return 'ipsec'
            elif protocol == 89:  # OSPF
                return 'ospf'
                
            return 'other'
            
        except Exception as e:
            print(f"Error categorizing service: {e}")
            return 'unknown'

    @staticmethod
    def is_well_known_port(port):
        """Check if port is in well-known range (0-1023)"""
        return 0 <= port <= 1023

    @staticmethod
    def get_protocol_name(protocol):
        """Get protocol name from number"""
        PROTOCOLS = {
            1: 'icmp',
            6: 'tcp',
            17: 'udp',
            47: 'gre',
            50: 'esp',
            89: 'ospf'
        }
        return PROTOCOLS.get(protocol, 'unknown')
