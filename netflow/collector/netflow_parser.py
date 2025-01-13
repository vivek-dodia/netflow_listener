# collector/netflow_parser.py

import socket
import struct
from collections import defaultdict

class NetFlowParser:
    NETFLOW_V9_HEADER = '!HHIIII'
    
    def __init__(self):
        self.templates = defaultdict(dict)
    
    def parse_header(self, data):
        """Parse NetFlow v9 header."""
        try:
            header_size = struct.calcsize(self.NETFLOW_V9_HEADER)
            if len(data) < header_size:
                raise ValueError(f"Packet too short for header: {len(data)} bytes")
                
            header = struct.unpack(self.NETFLOW_V9_HEADER, data[:header_size])
            header_dict = {
                'version': header[0],
                'count': header[1],
                'sys_uptime': header[2],
                'unix_secs': header[3],
                'sequence': header[4],
                'source_id': header[5]
            }
            return header_dict, header_size
        except struct.error as e:
            print(f"Error unpacking header: {e}")
            print(f"Data length: {len(data)}")
            print(f"First 20 bytes: {data[:20].hex()}")
            raise
    
    def parse_flowset_header(self, data):
        """Parse flowset header."""
        try:
            return struct.unpack('!HH', data[:4])
        except struct.error as e:
            print(f"Error unpacking flowset header: {e}")
            print(f"Data length: {len(data)}")
            print(f"First 8 bytes: {data[:8].hex()}")
            raise

    def parse_template(self, data):
        """Parse template flowset."""
        try:
            template_id, field_count = struct.unpack('!HH', data[:4])
            offset = 4
            template = []
            
            print(f"\nParsing template {template_id} with {field_count} fields")
            print(f"Template data length: {len(data)}")
            
            for _ in range(field_count):
                if offset + 4 > len(data):
                    raise ValueError("Template data truncated")
                    
                field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                template.append((field_type, field_length))
                print(f"  Field Type: {field_type}, Length: {field_length}")
                offset += 4
            
            self.templates[template_id] = template
            print(f"Successfully registered template {template_id}")
            return template
            
        except Exception as e:
            print(f"Error parsing template: {e}")
            print(f"Data: {data.hex()}")
            return None

    def parse_field(self, field_type, field_length, field_data):
        """Parse individual field data."""
        try:
            if not field_data or len(field_data) != field_length:
                print(f"Invalid field data length for type {field_type}: expected {field_length}, got {len(field_data) if field_data else 0}")
                return None
                
            if field_type in [1, 2]:  # Bytes/Packets
                if field_length == 4:
                    return struct.unpack('!I', field_data)[0]
                elif field_length == 8:
                    return struct.unpack('!Q', field_data)[0]
            elif field_type in [7, 11]:  # Source/Destination Port
                return struct.unpack('!H', field_data)[0]
            elif field_type in [8, 12]:  # Source/Destination IPv4
                return socket.inet_ntoa(field_data)
            elif field_type in [4, 6, 61]:  # Protocol, TCP Flags, Direction
                return struct.unpack('!B', field_data)[0]
            elif field_type in [21, 22]:  # Timestamps
                return struct.unpack('!I', field_data)[0]
                
        except Exception as e:
            print(f"Error parsing field type {field_type}: {e}")
            print(f"Field data: {field_data.hex()}")
        return None

    def parse_data(self, template_id, data, source_id):
        """Parse data flowset."""
        records = []
        if template_id not in self.templates:
            print(f"No template found for ID {template_id}")
            return records
            
        template = self.templates[template_id]
        record_length = sum(length for _, length in template)
        
        if record_length == 0:
            print(f"Invalid template {template_id}: zero record length")
            return records
            
        offset = 0
        while offset + record_length <= len(data):
            record = {'source_id': source_id}
            field_offset = offset
            
            for field_type, field_length in template:
                field_data = data[field_offset:field_offset + field_length]
                value = self.parse_field(field_type, field_length, field_data)
                
                field_map = {
                    1: 'bytes',
                    2: 'packets',
                    4: 'protocol',
                    7: 'src_port',
                    8: 'src_ip',
                    11: 'dst_port',
                    12: 'dst_ip',
                    6: 'tcp_flags',
                    61: 'direction',
                    21: 'last_switched',
                    22: 'first_switched'
                }
                
                if field_type in field_map and value is not None:
                    record[field_map[field_type]] = value
                    
                field_offset += field_length
            
            if self._validate_record(record):
                records.append(record)
            
            offset += record_length
            
        return records
    
    def _validate_record(self, record):
        """Validate that record has all required fields."""
        required_fields = ['bytes', 'packets', 'protocol', 'src_ip', 'dst_ip']
        return all(field in record for field in required_fields)
