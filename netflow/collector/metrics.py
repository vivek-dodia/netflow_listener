# collector/metrics.py

from prometheus_client import Counter, Gauge, Histogram, Info

class NetFlowMetrics:
    def __init__(self):
        # Basic flow metrics
        self.bytes_total = Counter(
            name='netflow_bytes_total',
            documentation='Total bytes processed',
            labelnames=['source_id', 'src_ip', 'dst_ip', 'protocol', 
                       'src_country', 'dst_country', 'src_asn', 'dst_asn', 'src_subnet', 'dst_subnet']
        )
        
        self.packets_total = Counter(
            name='netflow_packets_total',
            documentation='Total packets processed',
            labelnames=['source_id', 'src_ip', 'dst_ip', 'protocol', 
                       'src_country', 'dst_country', 'src_subnet', 'dst_subnet']
        )
        
        # Flow-specific metrics
        self.active_flows = Gauge(
            name='netflow_active_flows',
            documentation='Number of active flows',
            labelnames=['source_id', 'protocol', 'service']
        )
        
        self.flow_duration = Histogram(
            name='netflow_flow_duration_seconds',
            documentation='Duration of flows in seconds',
            labelnames=['source_id', 'protocol', 'service'],
            buckets=(0.1, 1, 5, 10, 30, 60, 300, 600, 1800, 3600)
        )

        # Flow rate metrics
        self.flow_rate = Gauge(
            name='netflow_flow_rate_bytes_sec',
            documentation='Current flow rate in bytes per second',
            labelnames=['source_id', 'protocol', 'direction', 'service']
        )

        self.packet_rate = Gauge(
            name='netflow_packet_rate_sec',
            documentation='Current packet rate per second',
            labelnames=['source_id', 'protocol', 'direction', 'service']
        )
        
        # Enhanced DNS metrics
        self.dns_queries = Counter(
            name='netflow_dns_queries_total',
            documentation='Total DNS queries',
            labelnames=['direction', 'source_id', 'query_size', 'client_subnet']
        )
        
        self.dns_response_size = Histogram(
            name='netflow_dns_response_bytes',
            documentation='DNS response size distribution',
            labelnames=['source_id', 'response_type', 'client_subnet'],
            buckets=(0, 512, 1024, 2048, 4096, 8192, 16384)
        )
        
        self.dns_clients = Counter(
            name='netflow_dns_clients_total',
            documentation='DNS client distribution',
            labelnames=['client_ip', 'source_id', 'client_subnet', 'client_asn']
        )

        self.dns_response_time = Histogram(
            name='netflow_dns_response_time_seconds',
            documentation='DNS response time distribution',
            labelnames=['source_id', 'client_subnet'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
        )

        self.dns_error_responses = Counter(
            name='netflow_dns_error_responses_total',
            documentation='DNS error response distribution',
            labelnames=['error_type', 'client_subnet', 'source_id']
        )
        
        # Service-based metrics
        self.service_bytes = Counter(
            name='netflow_service_bytes_total',
            documentation='Bytes by service category',
            labelnames=['service', 'direction', 'source_id', 'src_subnet', 'dst_subnet']
        )
        
        self.service_packets = Counter(
            name='netflow_service_packets_total',
            documentation='Packets by service category',
            labelnames=['service', 'direction', 'source_id', 'src_subnet', 'dst_subnet']
        )

        self.service_connections = Counter(
            name='netflow_service_connections_total',
            documentation='Total connections by service',
            labelnames=['service', 'direction', 'source_id', 'status']
        )
        
        # Flow size metrics
        self.flow_size_category = Counter(
            name='netflow_flow_size_category_total',
            documentation='Flow counts by size category',
            labelnames=['category', 'protocol', 'source_id', 'service']
        )
        
        self.flow_size = Histogram(
            name='netflow_flow_size_bytes',
            documentation='Distribution of flow sizes in bytes',
            labelnames=['source_id', 'protocol', 'service', 'direction'],
            buckets=(64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072)
        )
        
        # Performance metrics
        self.processing_time = Histogram(
            name='netflow_processing_time_seconds',
            documentation='Time taken to process each flow',
            labelnames=['operation', 'template_id'],
            buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
        )
        
        self.error_counter = Counter(
            name='netflow_processing_errors_total',
            documentation='Total number of processing errors',
            labelnames=['error_type', 'source_id', 'template_id']
        )
        
        # Traffic direction metrics
        self.direction_bytes = Counter(
            name='netflow_direction_bytes_total',
            documentation='Bytes by traffic direction',
            labelnames=['direction', 'source_id', 'src_subnet', 'dst_subnet']
        )
        
        self.direction_packets = Counter(
            name='netflow_direction_packets_total',
            documentation='Packets by traffic direction',
            labelnames=['direction', 'source_id', 'src_subnet', 'dst_subnet']
        )
        
        # Protocol metrics
        self.protocol_distribution = Counter(
            name='netflow_protocol_distribution_total',
            documentation='Distribution of protocols',
            labelnames=['protocol', 'source_id', 'direction']
        )

        # TCP specific metrics
        self.tcp_flags = Counter(
            name='netflow_tcp_flags_total',
            documentation='TCP flag distribution',
            labelnames=['flag_type', 'source_id', 'direction']
        )

        self.tcp_retransmits = Counter(
            name='netflow_tcp_retransmits_total',
            documentation='TCP retransmission count',
            labelnames=['source_id', 'src_subnet', 'dst_subnet']
        )

        # Anomaly detection metrics
        self.rate_limit_exceeded = Counter(
            name='netflow_rate_limit_exceeded_total',
            documentation='Count of rate limit violations',
            labelnames=['source_id', 'src_ip', 'limit_type']
        )

        self.unusual_flow_size = Counter(
            name='netflow_unusual_flow_size_total',
            documentation='Count of unusually sized flows',
            labelnames=['source_id', 'direction', 'size_type']
        )

        # Metadata metrics
        self.collector_info = Info(
            'netflow_collector',
            'Information about the NetFlow collector'
        )

        # Subnet metrics
        self.subnet_traffic = Counter(
            name='netflow_subnet_traffic_bytes_total',
            documentation='Traffic by subnet',
            labelnames=['subnet', 'direction', 'source_id']
        )

        # Connection tracking
        self.concurrent_connections = Gauge(
            name='netflow_concurrent_connections',
            documentation='Number of concurrent connections',
            labelnames=['service', 'source_id', 'src_subnet']
        )

        # Traffic pattern metrics
        self.traffic_pattern = Counter(
            name='netflow_traffic_pattern_total',
            documentation='Traffic patterns by time period',
            labelnames=['period', 'direction', 'service']
        )
