import socket
from .collector import NetFlowParser, NetFlowMetrics, GeoIPHandler
from .utils import ServiceMapper, FlowCategorizer

class NetFlowListener:
    def __init__(self, netflow_port=2055, prometheus_port=9500, geoip_db=None):
        self.netflow_port = netflow_port
        self.prometheus_port = prometheus_port
        self.parser = NetFlowParser()
        self.metrics = NetFlowMetrics()
        self.geoip = GeoIPHandler(geoip_db)
        self.service_mapper = ServiceMapper()
        self.flow_categorizer = FlowCategorizer()
        
    def start(self):
        print(f"Starting NetFlow listener on port {self.netflow_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.netflow_port))
        
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
        header = self.parser.parse_header(data)
        version, count, sys_uptime, unix_secs, seq_number, source_id = header
        
        if version != 9:
            print(f"Unsupported NetFlow version: {version}")
            return
            
        offset = struct.calcsize(self.parser.NETFLOW_V9_HEADER)
        for _ in range(count):
            try:
                flowset_id, length = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                
                if flowset_id == 0:  # Template flowset
                    self.parser.parse_template(data[offset:offset+length-4])
                else:  # Data flowset
                    flow = self.parser.parse_data(flowset_id, data[offset:offset+length-4])
                    self._process_flow(flow)
                
                offset += length - 4
            except struct.error:
                break
                
    def _process_flow(self, flow):
        if not flow:
            return
            
        self.metrics.update_metrics(flow)
        
        # Example processing
        src_service = self.service_mapper.get_service(flow.get('src_port', 0))
        dst_service = self.service_mapper.get_service(flow.get('dst_port', 0))
        flow_type = self.flow_categorizer.categorize_flow(flow)
        
        print(f"Flow: {flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)} -> "
              f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}")
        print(f"  Type: {flow_type}")
        print(f"  Services: {src_service} -> {dst_service}")
        print(f"  Bytes: {flow.get('bytes', 0)}")
        print(f"  Packets: {flow.get('packets', 0)}")

if __name__ == '__main__':
    listener = NetFlowListener()
    listener.start()
