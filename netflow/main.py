# main.py

import socket
import os
from datetime import datetime
from prometheus_client import start_http_server
from collector.netflow_parser import NetFlowParser
from collector.metrics import NetFlowMetrics
from collector.geoip_handler import GeoIPHandler
from utils.service_mapper import ServiceMapper
from utils.flow_categorizer import FlowCategorizer

class NetFlowCollector:
    def __init__(self, netflow_port=2055, prometheus_port=9500):
        self.netflow_port = netflow_port
        self.prometheus_port = prometheus_port
        self.parser = NetFlowParser()
        self.metrics = NetFlowMetrics()
        
        # Construct absolute path to GeoIP database
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        geoip_path = os.path.join(base_dir, 'geoip', 'GeoLite2-City.mmdb')
        
        if not os.path.exists(geoip_path):
            print(f"Warning: GeoIP database not found at {geoip_path}")
            print("GeoIP lookups will be disabled")
            
        self.geoip = GeoIPHandler(geoip_path)
        self.server_ip = '148.76.96.103'  # Your DNS server IP

        # Set collector info
        self.metrics.collector_info.info({
            'version': '1.0',
            'start_time': datetime.now().isoformat(),
            'server_ip': self.server_ip,
            'geoip_enabled': str(os.path.exists(geoip_path))
        })
    
    def start(self):
        """Start the collector."""
        try:
            print(f"Starting Prometheus metrics server on port {self.prometheus_port}")
            start_http_server(self.prometheus_port)
            
            print(f"Starting NetFlow listener on port {self.netflow_port}")
            self._start_netflow_listener()
        except Exception as e:
            print(f"Error starting collector: {e}")
            self.metrics.error_counter.labels(
                error_type='startup',
                source_id='system',
                template_id='none'
            ).inc()
            raise
    
    def _start_netflow_listener(self):
        """Start UDP listener for NetFlow data."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('0.0.0.0', self.netflow_port))
            print("NetFlow listener ready")
            
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    print(f"Received packet from {addr[0]}:{addr[1]}")
                    self._handle_packet(data)
                except KeyboardInterrupt:
                    print("\nShutting down...")
                    break
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    self.metrics.error_counter.labels(
                        error_type='packet_processing',
                        source_id='system',
                        template_id='none'
                    ).inc()
                    continue
                    
        except Exception as e:
            print(f"Error binding to port {self.netflow_port}: {e}")
            raise
        finally:
            try:
                sock.close()
                self.geoip.close()
            except Exception as e:
                print(f"Error during shutdown: {e}")
    
    def _handle_packet(self, data):
        """Process incoming NetFlow packet."""
        try:
            header, offset = self.parser.parse_header(data)
            
            if header['version'] != 9:
                print(f"Unsupported NetFlow version: {header['version']}")
                self.metrics.error_counter.labels(
                    error_type='unsupported_version',
                    source_id=str(header.get('source_id', 'unknown')),
                    template_id='none'
                ).inc()
                return
            
            while offset < len(data):
                try:
                    flowset_id, length = self.parser.parse_flowset_header(data[offset:])
                    
                    if length < 4:  # Basic sanity check
                        print(f"Invalid flowset length: {length}")
                        break
                        
                    flowset_data = data[offset+4:offset+length]
                    
                    if flowset_id == 0:  # Template flowset
                        self.parser.parse_template(flowset_data)
                    else:  # Data flowset
                        records = self.parser.parse_data(flowset_id, flowset_data, header['source_id'])
                        for record in records:
                            record['template_id'] = flowset_id
                            self._process_flow(record)
                    
                    offset += length
                    
                except Exception as e:
                    print(f"Error processing flowset: {e}")
                    self.metrics.error_counter.labels(
                        error_type='flowset_processing',
                        source_id=str(header.get('source_id', 'unknown')),
                        template_id=str(flowset_id)
                    ).inc()
                    break
                
        except Exception as e:
            print(f"Error processing packet header: {e}")
            self.metrics.error_counter.labels(
                error_type='header_processing',
                source_id='unknown',
                template_id='none'
            ).inc()

    def _get_subnets(self, src_ip, dst_ip):
        """Calculate /24 subnets for IPs."""
        try:
            src_subnet = '.'.join(src_ip.split('.')[:3]) + '.0/24'
            dst_subnet = '.'.join(dst_ip.split('.')[:3]) + '.0/24'
            return src_subnet, dst_subnet
        except:
            return 'unknown/24', 'unknown/24'
    
    def _process_flow(self, record):
        """Process a flow record and update metrics."""
        try:
            # Validate required fields
            required_fields = ['source_id', 'src_ip', 'dst_ip', 'protocol', 'bytes', 'packets']
            if not all(field in record for field in required_fields):
                missing = [f for f in required_fields if f not in record]
                print(f"Incomplete flow record, missing: {missing}")
                return
            
            start_time = datetime.now()
            
            # Basic flow information
            source_id = str(record['source_id'])
            src_ip = record['src_ip']
            dst_ip = record['dst_ip']
            protocol = str(record['protocol'])
            bytes_ = record['bytes']
            packets = record['packets']
            src_subnet, dst_subnet = self._get_subnets(src_ip, dst_ip)
            
            # Get GeoIP information
            src_info = self.geoip.get_location_info(src_ip)
            dst_info = self.geoip.get_location_info(dst_ip)
            
            # Get service and direction information
            service = ServiceMapper.categorize_service(record)
            direction = FlowCategorizer.determine_direction(dst_ip, self.server_ip)
            size_category = FlowCategorizer.categorize_size(bytes_)
            
            # Update basic flow metrics
            self.metrics.bytes_total.labels(
                source_id=source_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_country=src_info['country'],
                dst_country=dst_info['country'],
                src_asn=src_info['asn'],
                dst_asn=dst_info['asn'],
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(bytes_)
            
            self.metrics.packets_total.labels(
                source_id=source_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_country=src_info['country'],
                dst_country=dst_info['country'],
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(packets)
            
            # Update service metrics
            self.metrics.service_bytes.labels(
                service=service,
                direction=direction,
                source_id=source_id,
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(bytes_)
            
            self.metrics.service_packets.labels(
                service=service,
                direction=direction,
                source_id=source_id,
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(packets)
            
            # Update service connections
            self.metrics.service_connections.labels(
                service=service,
                direction=direction,
                source_id=source_id,
                status='established'
            ).inc()
            
            # Update flow size metrics
            self.metrics.flow_size_category.labels(
                category=size_category,
                protocol=protocol,
                source_id=source_id,
                service=service
            ).inc()
            
            # Update flow size distribution
            self.metrics.flow_size.labels(
                source_id=source_id,
                protocol=protocol,
                service=service,
                direction=direction
            ).observe(bytes_)
            
            # Update active flows gauge
            self.metrics.active_flows.labels(
                source_id=source_id,
                protocol=protocol,
                service=service
            ).inc()
            
            # Update traffic direction metrics
            self.metrics.direction_bytes.labels(
                direction=direction,
                source_id=source_id,
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(bytes_)
            
            self.metrics.direction_packets.labels(
                direction=direction,
                source_id=source_id,
                src_subnet=src_subnet,
                dst_subnet=dst_subnet
            ).inc(packets)
            
            # Update protocol distribution
            self.metrics.protocol_distribution.labels(
                protocol=protocol,
                source_id=source_id,
                direction=direction
            ).inc()
            
            # Update subnet traffic
            self.metrics.subnet_traffic.labels(
                subnet=src_subnet,
                direction=direction,
                source_id=source_id
            ).inc(bytes_)
            
            # DNS-specific metrics
            if service == 'dns':
                if direction == 'inbound':
                    self.metrics.dns_queries.labels(
                        direction=direction,
                        source_id=source_id,
                        query_size=str(bytes_),
                        client_subnet=src_subnet
                    ).inc()
                    
                    self.metrics.dns_clients.labels(
                        client_ip=src_ip,
                        source_id=source_id,
                        client_subnet=src_subnet,
                        client_asn=src_info['asn']
                    ).inc()
                else:
                    response_type = 'standard' if bytes_ <= 512 else 'edns'
                    self.metrics.dns_response_size.labels(
                        source_id=source_id,
                        response_type=response_type,
                        client_subnet=dst_subnet
                    ).observe(bytes_)
            
            # TCP-specific metrics
            if protocol == '6' and 'tcp_flags' in record:
                flags = record['tcp_flags']
                for flag, bit in [('SYN', 0x02), ('ACK', 0x10), ('FIN', 0x01), ('RST', 0x04)]:
                    if flags & bit:
                        self.metrics.tcp_flags.labels(
                            flag_type=flag,
                            source_id=source_id,
                            direction=direction
                        ).inc()
            
            # Flow duration metrics
            if 'first_switched' in record and 'last_switched' in record:
                duration = record['last_switched'] - record['first_switched']
                if duration >= 0:
                    self.metrics.flow_duration.labels(
                        source_id=source_id,
                        protocol=protocol,
                        service=service
                    ).observe(duration)
            
            # Performance metrics
            process_time = (datetime.now() - start_time).total_seconds()
            self.metrics.processing_time.labels(
                operation='flow_processing',
                template_id=str(record.get('template_id', 'unknown'))
            ).observe(process_time)
            
            # Print flow information
            print(f"\nProcessed flow: {src_ip}:{record.get('src_port', '?')} -> "
                  f"{dst_ip}:{record.get('dst_port', '?')} "
                  f"Proto: {protocol} Service: {service} "
                  f"Bytes: {bytes_} Packets: {packets}")
            
        except Exception as e:
            print(f"Error processing flow record: {e}")
            self.metrics.error_counter.labels(
                error_type='flow_processing',
                source_id=str(record.get('source_id', 'unknown')),
                template_id=str(record.get('template_id', 'unknown'))
            ).inc()

def main():
    try:
        # Allow custom ports via environment variables
        netflow_port = int(os.environ.get('NETFLOW_PORT', 2055))
        prometheus_port = int(os.environ.get('PROMETHEUS_PORT', 9500))
        
        collector = NetFlowCollector(
            netflow_port=netflow_port,
            prometheus_port=prometheus_port
        )
        collector.start()
    except Exception as e:
        print(f"Fatal error: {e}")
        raise

if __name__ == '__main__':
    main()
