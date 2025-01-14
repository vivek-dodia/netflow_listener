# utils/protocol_detector.py

class ProtocolDetector:
    # Protocol definitions with ports and characteristics
    PROTOCOL_MAPPINGS = {
        'DNS': {'ports': [53], 'udp': True},
        'HTTP': {'ports': [80, 8080]},
        'HTTPS': {'ports': [443, 8443]},
        'SSH': {'ports': [22]},
        'SMTP': {'ports': [25, 587]},
        'NTP': {'ports': [123], 'udp': True},
        'SNMP': {'ports': [161, 162], 'udp': True},
        'ICMP': {'protocol': 1},
        'MySQL': {'ports': [3306]},
        'PostgreSQL': {'ports': [5432]},
        'MongoDB': {'ports': [27017, 27018, 27019]},
        'Redis': {'ports': [6379]},
        'LDAP': {'ports': [389]},
        'LDAPS': {'ports': [636]},
        'SMB': {'ports': [445]},
        'RDP': {'ports': [3389]},
        'DHCP': {'ports': [67, 68], 'udp': True},
        'SYSLOG': {'ports': [514]},
        'TFTP': {'ports': [69], 'udp': True},
    }

    @classmethod
    def detect_protocol(cls, flow):
        """Detect protocol based on flow characteristics."""
        try:
            src_port = flow.get('src_port', 0)
            dst_port = flow.get('dst_port', 0)
            protocol_num = flow.get('protocol', 0)
            ports = [src_port, dst_port]

            # Check ICMP first
            if protocol_num == 1:
                return 'ICMP'

            # Check UDP/TCP first
            is_udp = protocol_num == 17
            is_tcp = protocol_num == 6

            # Try to match known protocols
            for proto_name, proto_def in cls.PROTOCOL_MAPPINGS.items():
                # Skip if protocol doesn't match UDP/TCP requirement
                if proto_def.get('udp') and not is_udp:
                    continue
                if not proto_def.get('udp') and not proto_def.get('protocol') and not is_tcp:
                    continue

                # Check protocol number if specified
                if proto_def.get('protocol'):
                    if protocol_num == proto_def['protocol']:
                        return proto_name
                    continue

                # Check ports
                if any(p in proto_def['ports'] for p in ports if p > 0):
                    return proto_name

            # Default categorization
            if is_tcp:
                if src_port > 32767 or dst_port > 32767:
                    return 'TCP_EPHEMERAL'
                return 'TCP_OTHER'
            elif is_udp:
                if src_port > 32767 or dst_port > 32767:
                    return 'UDP_EPHEMERAL'
                return 'UDP_OTHER'
            
            return 'UNKNOWN'

        except Exception as e:
            print(f"Protocol detection error: {str(e)}")
            return 'UNKNOWN'

    @classmethod
    def get_protocol_category(cls, protocol_name):
        """Get high-level category for protocol."""
        categories = {
            'WEB': ['HTTP', 'HTTPS'],
            'DATABASE': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis'],
            'INFRASTRUCTURE': ['DNS', 'DHCP', 'NTP', 'SNMP', 'SYSLOG'],
            'SECURITY': ['SSH', 'LDAPS'],
            'FILE_SHARING': ['SMB', 'TFTP'],
            'MAIL': ['SMTP'],
            'REMOTE_ACCESS': ['RDP'],
            'DIRECTORY': ['LDAP']
        }

        for category, protocols in categories.items():
            if protocol_name in protocols:
                return category

        if protocol_name in ['TCP_EPHEMERAL', 'TCP_OTHER']:
            return 'TCP'
        elif protocol_name in ['UDP_EPHEMERAL', 'UDP_OTHER']:
            return 'UDP'
        elif protocol_name == 'ICMP':
            return 'ICMP'

        return 'OTHER'

    @classmethod
    def is_known_protocol(cls, protocol_name):
        """Check if protocol is known/registered."""
        return protocol_name in cls.PROTOCOL_MAPPINGS or protocol_name in [
            'TCP_EPHEMERAL', 'TCP_OTHER', 'UDP_EPHEMERAL', 'UDP_OTHER', 'ICMP', 'UNKNOWN'
        ]
