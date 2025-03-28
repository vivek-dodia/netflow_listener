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
from utils.protocol_detector import ProtocolDetector
from utils.behavior_analyzer import BehaviorAnalyzer
from dotenv import load_dotenv
import logging
import logging.handlers

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger('NetFlowCollector')
logger.setLevel(logging.INFO)

# Configure syslog if environment variables are set
syslog_server = os.getenv('SYSLOG_SERVER')
syslog_port = int(os.getenv('SYSLOG_PORT', 514))
syslog_prefix = os.getenv('SYSLOG_PREFIX', 'netflow')

if syslog_server:
    syslog_handler = logging.handlers.SysLogHandler(
        address=(syslog_server, syslog_port),
	socktype=socket.SOCK_DGRAM
    )
    formatter = logging.Formatter(f'{syslog_prefix}: %(message)s')
    syslog_handler.setFormatter(formatter)
    logger.addHandler(syslog_handler)

class NetFlowCollector:
    def __init__(self, netflow_port=2055, prometheus_port=9500):
        self.netflow_port = netflow_port
        self.prometheus_port = prometheus_port
        self.parser = NetFlowParser()
        self.metrics = NetFlowMetrics()
        self.protocol_detector = ProtocolDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Construct absolute path to GeoIP database
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        geoip_path = os.path.join(base_dir, 'geoip', 'GeoLite2-City.mmdb')
        
        if not os.path.exists(geoip_path):
            print(f"Warning: GeoIP database not found at {geoip_path}")
            print("GeoIP lookups will be disabled")
            logger.warning(f"GeoIP database not found at {geoip_path}")
            logger.warning("GeoIP lookups will be disabled")
            
        self.geoip = GeoIPHandler(geoip_path)
        self.server_ip = '148.76.96.103'  # Your DNS server IP

        # Set collector info
        self.metrics.collector_info.info({
            'version': '1.0',
            'start_time': datetime.now().isoformat(),
            'server_ip': self.server_ip,
            'geoip_enabled': str(os.path.exists(geoip_path))
        })
        logger.info(f"NetFlow Collector initialized - NetFlow Port: {netflow_port}, Prometheus Port: {prometheus_port}")

    def start(self):
        """Start the collector."""
        try:
            print(f"Starting Prometheus metrics server on port {self.prometheus_port}")
            logger.info(f"Starting Prometheus metrics server on port {self.prometheus_port}")
            start_http_server(self.prometheus_port)
            
            print(f"Starting NetFlow listener on port {self.netflow_port}")
            logger.info(f"Starting NetFlow listener on port {self.netflow_port}")
            self._start_netflow_listener()
        except Exception as e:
            error_msg = f"Error starting collector: {e}"
            print(error_msg)
            logger.error(error_msg)
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
            logger.info("NetFlow listener ready and accepting connections")
            
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    self._handle_packet(data)
                except KeyboardInterrupt:
                    print("\nShutting down...")
                    logger.info("Received shutdown signal, stopping collector...")
                    break
                except Exception as e:
                    error_msg = f"Error processing packet: {e}"
                    logger.error(error_msg)
                    self.metrics.error_counter.labels(
                        error_type='packet_processing',
                        source_id='system',
                        template_id='none'
                    ).inc()
                    continue
                    
        except Exception as e:
            error_msg = f"Error binding to port {self.netflow_port}: {e}"
            print(error_msg)
            logger.error(error_msg)
            raise
        finally:
            try:
                sock.close()
                self.geoip.close()
                logger.info("NetFlow collector shutdown completed")
            except Exception as e:
                error_msg = f"Error during shutdown: {e}"
                logger.error(error_msg)

    def _handle_packet(self, data):
        """Process incoming NetFlow packet."""
        try:
            header, offset = self.parser.parse_header(data)
            
            if header['version'] != 9:
                error_msg = f"Unsupported NetFlow version: {header['version']}"
                logger.warning(error_msg)
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
                        error_msg = f"Invalid flowset length: {length}"
                        logger.warning(error_msg)
                        break
                        
                    flowset_data = data[offset+4:offset+length]
                    
                    if flowset_id == 0:  # Template flowset
                        self.parser.parse_template(flowset_data)
                        logger.info(f"Processed template flowset ID: {flowset_id}")
                    else:  # Data flowset
                        records = self.parser.parse_data(flowset_id, flowset_data, header['source_id'])
                        for record in records:
                            record['template_id'] = flowset_id
                            self._process_flow(record)
                    
                    offset += length
                    
                except Exception as e:
                    error_msg = f"Error processing flowset: {e}"
                    logger.error(error_msg)
                    self.metrics.error_counter.labels(
                        error_type='flowset_processing',
                        source_id=str(header.get('source_id', 'unknown')),
                        template_id=str(flowset_id)
                    ).inc()
                    break
                
        except Exception as e:
            error_msg = f"Error processing packet header: {e}"
            logger.error(error_msg)
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
            logger.warning(f"Error calculating subnets for IPs: {src_ip}, {dst_ip}")
            return 'unknown/24', 'unknown/24'

    def _check_for_anomalies(self, flow, behavior):
        """Check for traffic anomalies."""
        anomalies = []
        if behavior.get('intensity') == 'HIGH':
            anomalies.append('high_intensity')
            logger.warning(f"High intensity traffic detected from {flow.get('src_ip')} to {flow.get('dst_ip')}")
        if behavior.get('risk_level') == 'HIGH':
            anomalies.append('high_risk')
            logger.warning(f"High risk behavior detected from {flow.get('src_ip')} to {flow.get('dst_ip')}")
        if flow.get('bytes', 0) > 1000000:  # 1MB+
            anomalies.append('large_flow')
            logger.warning(f"Large flow detected: {flow.get('bytes')} bytes from {flow.get('src_ip')} to {flow.get('dst_ip')}")
        return anomalies

    def _is_private_ip(self, ip):
        """Check if IP address is private (RFC1918)."""
        try:
            # Convert IP string to integers for efficient comparison
            parts = [int(part) for part in ip.split('.')]
            return (
                (parts[0] == 10) or                                # 10.0.0.0/8
                (parts[0] == 172 and 16 <= parts[1] <= 31) or     # 172.16.0.0/12
                (parts[0] == 192 and parts[1] == 168) or          # 192.168.0.0/16
                (parts[0] == 127) or                              # localhost
                (parts[0] == 169 and parts[1] == 254)             # link-local
            )
        except:
            return False

    def _process_flow(self, record):
        """Process a flow record with enhanced analysis."""
        try:
            # Validate required fields
            required_fields = ['source_id', 'src_ip', 'dst_ip', 'protocol', 'bytes', 'packets']
            if not all(field in record for field in required_fields):
                missing = [f for f in required_fields if f not in record]
                error_msg = f"Incomplete flow record, missing: {missing}"
                logger.warning(error_msg)
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
            
            # Service detection first (more reliable)
            service = ServiceMapper.categorize_service(record)
            
            # Protocol detection (use service if protocol detection fails)
            detected_protocol = self.protocol_detector.detect_protocol(record)
            if detected_protocol == 'UNKNOWN' and service != 'unknown':
                detected_protocol = service.upper()
            
            # Get direction and behavior info
            direction = FlowCategorizer.determine_direction(dst_ip, self.server_ip)
            size_category = FlowCategorizer.categorize_size(bytes_)
            behavior = self.behavior_analyzer.analyze_flow(record, detected_protocol)

            # Get GeoIP information
            #src_info = self.geoip.get_location_info(src_ip)
            #dst_info = self.geoip.get_location_info(dst_ip)
            
            if self._is_private_ip(src_ip):
                src_info = {
                    'country': 'PRIVATE',
                    'asn': 'RFC1918'
                }
            else:
                src_info = self.geoip.get_location_info(src_ip)

            if self._is_private_ip(dst_ip):
                dst_info = {
                    'country': 'PRIVATE',
                    'asn': 'RFC1918'
                }
            else:
                dst_info = self.geoip.get_location_info(dst_ip)

            # Check for anomalies
            anomalies = self._check_for_anomalies(record, behavior)
            if anomalies:
                for anomaly in anomalies:
                    self.metrics.connection_anomalies.labels(
                        anomaly_type=anomaly,
                        src_subnet=src_subnet,
                        dst_subnet=dst_subnet,
                        protocol=detected_protocol
                    ).inc()

            # Security metrics based on behavior
            if behavior.get('risk_level') == 'HIGH':
                self.metrics.security_events.labels(
                    event_type=behavior.get('type', 'unknown'),
                    severity='high',
                    src_subnet=src_subnet,
                    dst_subnet=dst_subnet,
                    protocol=detected_protocol
                ).inc()
                logger.warning(f"High risk behavior detected - Type: {behavior.get('type', 'unknown')}, Source: {src_subnet}, Protocol: {detected_protocol}")

            # Track behavior patterns
            self.metrics.behavior_patterns.labels(
                pattern_type=behavior.get('pattern', 'unknown'),
                protocol=detected_protocol,
                src_subnet=src_subnet,
                risk_level=behavior.get('risk_level', 'LOW')
            ).inc()

            # Basic flow metrics
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
            
            # Service metrics
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
            
            # Application metrics for specific protocols
            if detected_protocol in ['HTTP2', 'QUIC', 'MONGODB', 'POSTGRESQL', 'DNS']:
                self.metrics.app_traffic.labels(
                    app_type=detected_protocol,
                    operation_type=behavior.get('type', 'unknown'),
                    src_subnet=src_subnet,
                    direction=direction
                ).inc(bytes_)

            # Flow size metrics
            self.metrics.flow_size_category.labels(
                category=size_category,
                protocol=protocol,
                source_id=source_id,
                service=service
            ).inc()
            
            # DNS-specific processing
            if service == 'dns':
                self._process_dns_flow(record, src_ip, src_info, src_subnet, dst_subnet, 
                                    direction, source_id, bytes_)

            # TCP-specific processing
            if protocol == '6' and 'tcp_flags' in record:
                self._process_tcp_flow(record, source_id, direction, src_subnet, dst_subnet)
            
            # Duration and performance metrics
            if 'first_switched' in record and 'last_switched' in record:
                duration = record['last_switched'] - record['first_switched']
                if duration >= 0:
                    self.metrics.flow_duration.labels(
                        source_id=source_id,
                        protocol=protocol,
                        service=service
                    ).observe(duration)

            # Performance metric
            process_time = (datetime.now() - start_time).total_seconds()
            self.metrics.processing_time.labels(
                operation='flow_processing',
                template_id=str(record.get('template_id', 'unknown'))
            ).observe(process_time)
            
        except Exception as e:
            error_msg = f"Error processing flow record: {e}"
            logger.error(error_msg)
            self.metrics.error_counter.labels(
                error_type='flow_processing',
                source_id=str(record.get('source_id', 'unknown')),
                template_id=str(record.get('template_id', 'unknown'))
            ).inc()

    def _process_dns_flow(self, record, src_ip, src_info, src_subnet, dst_subnet, 
                         direction, source_id, bytes_):
        """Process DNS-specific flow metrics."""
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

    def _process_tcp_flow(self, record, source_id, direction, src_subnet, dst_subnet):
        """Process TCP-specific flow metrics."""
        flags = record['tcp_flags']
        for flag, bit in [('SYN', 0x02), ('ACK', 0x10), ('FIN', 0x01), ('RST', 0x04)]:
            if flags & bit:
                self.metrics.tcp_flags.labels(
                    flag_type=flag,
                    source_id=source_id,
                    direction=direction
                ).inc()
        
        # Check for potential SYN flood
        if flags & 0x02 and not flags & 0x10:  # SYN without ACK
            self.metrics.security_events.labels(
                event_type='syn_flood',
                severity='medium',
                src_subnet=src_subnet,
                dst_subnet=dst_subnet,
                protocol='TCP'
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
