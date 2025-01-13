import socket
import struct
from collections import defaultdict

class NetFlowParser:
    NETFLOW_V9_HEADER = '!HHIIII'
    
    def __init__(self):
        self.templates = defaultdict(dict)
        
    def parse_header(self, data):
        header_size = struct.calcsize(self.NETFLOW_V9_HEADER)
        return struct.unpack(self.NETFLOW_V9_HEADER, data[:header_size])
        
    def parse_template(self, data):
        template_id, field_count = struct.unpack('!HH', data[:4])
        offset = 4
        template = []
        
        for _ in range(field_count):
            field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
            template.append((field_type, field_length))
            offset += 4
            
        self.templates[template_id] = template
        return template
        
    def parse_data(self, template_id, data):
        if template_id not in self.templates:
            return None
            
        template = self.templates[template_id]
        offset = 0
        record = {}
        
        for field_type, field_length in template:
            if field_type == 8:  # Source IP
                record['src_ip'] = socket.inet_ntoa(data[offset:offset+4])
            elif field_type == 12:  # Destination IP
                record['dst_ip'] = socket.inet_ntoa(data[offset:offset+4])
            elif field_type == 7:  # Source Port
                record['src_port'] = struct.unpack('!H', data[offset:offset+2])[0]
            elif field_type == 11:  # Destination Port
                record['dst_port'] = struct.unpack('!H', data[offset:offset+2])[0]
            elif field_type == 1:  # Bytes
                record['bytes'] = struct.unpack('!I', data[offset:offset+4])[0]
            elif field_type == 2:  # Packets
                record['packets'] = struct.unpack('!I', data[offset:offset+4])[0]
            elif field_type == 4:  # Protocol
                record['protocol'] = struct.unpack('!B', data[offset:offset+1])[0]
            
            offset += field_length
            
        return record
