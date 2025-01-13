import socket
import struct
import geoip2.database
from prometheus_client import start_http_server, Gauge
import os
from collections import defaultdict

class NetFlowListener:
    # NetFlow v9 header format
    NETFLOW_V9_HEADER = '!HHIIII'
    
    def __init__(self, netflow_port=2055, prometheus_port=9500, geoip_db='geoip/GeoLite2-City.mmdb'):
        self.netflow_port = netflow_port
        self.prometheus_port = prometheus_port
        self.templates = defaultdict(dict)
        
        # Initialize GeoIP reader
        if os.path.exists(geoip_db):
            self.geoip_reader = geoip2.database.Reader(geoip_db)
            print(f"Loaded GeoIP database from {geoip_db}")
        else:
            self.geoip_reader = None
            print(f"Warning: GeoIP database not found. GeoIP lookups will be disabled.")
        
        # Prometheus metrics
        self.bytes_total = Gauge('netflow_bytes_total', 'Total bytes processed')
        self.packets_total = Gauge('netflow_packets_total', 'Total packets processed')
        self.active_flows = Gauge('netflow_active_flows', 'Number of active flows')
        
    def start(self):
        print(f"Starting Prometheus metrics server on port {self.prometheus_port}")
        start_http_server(self.prometheus_port)
        
        print(f"Starting NetFlow listener on port {self.netflow_port}")
        self._start_netflow_listener()
        
    def _start_netflow_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.netflow_port))
        
        print("NetFlow listener ready")
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                self._process_packet(data)
            except KeyboardInterrupt:
                print("\nShutting down...")
                break
            except Exception as e:
                print(f"Error processing packet: {e}")
                
    def _process_packet(self, data):
        # Parse NetFlow v9 header
        header_size = struct.calcsize(self.NETFLOW_V9_HEADER)
        header = struct.unpack(self.NETFLOW_V9_HEADER, data[:header_size])
        
        version, count, sys_uptime, unix_secs, seq_number, source_id = header
        
        if version != 9:
            print(f"Unsupported NetFlow version: {version}")
            return
        
        offset = header_size
        for _ in range(count):
            try:
                flowset_id, length = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                
                if flowset_id == 0:  # Template flowset
                    self._process_template(data[offset:offset+length-4])
                else:  # Data flowset
                    self._process_data(flowset_id, data[offset:offset+length-4])
                
                offset += length - 4
            except struct.error:
                break
                
    def _process_template(self, data):
        template_id, field_count = struct.unpack('!HH', data[:4])
        offset = 4
        
        template = []
        for _ in range(field_count):
            field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
            template.append((field_type, field_length))
            offset += 4
            
        self.templates[template_id] = template
        
    def _process_data(self, template_id, data):
        if template_id not in self.templates:
            return
            
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
            
        self._process_flow(record)
            
    def _process_flow(self, flow):
        if not flow:
            return
            
        # Update Prometheus metrics
        self.bytes_total.inc(flow.get('bytes', 0))
        self.packets_total.inc(flow.get('packets', 0))
        
        # GeoIP enrichment if database is available
        if self.geoip_reader and 'src_ip' in flow and 'dst_ip' in flow:
            try:
                src_location = self.geoip_reader.city(flow['src_ip'])
                dst_location = self.geoip_reader.city(flow['dst_ip'])
                print(f"Flow: {flow['src_ip']}:{flow.get('src_port', 0)} -> {flow['dst_ip']}:{flow.get('dst_port', 0)}")
                print(f"  Protocol: {flow.get('protocol', 'unknown')}")
                print(f"  Bytes: {flow.get('bytes', 0)}")
                print(f"  Packets: {flow.get('packets', 0)}")
                print(f"  Source Location: {src_location.city.name}, {src_location.country.name}")
                print(f"  Destination Location: {dst_location.city.name}, {dst_location.country.name}")
            except Exception as e:
                print(f"GeoIP lookup failed: {e}")
        else:
            print(f"Flow: {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> {flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}")
            print(f"  Protocol: {flow.get('protocol', 'unknown')}")
            print(f"  Bytes: {flow.get('bytes', 0)}")
            print(f"  Packets: {flow.get('packets', 0)}")

if __name__ == '__main__':
    listener = NetFlowListener()
    listener.start()
