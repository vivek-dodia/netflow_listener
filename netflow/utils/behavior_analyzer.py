# utils/behavior_analyzer.py

from collections import defaultdict
import time

class BehaviorAnalyzer:
    def __init__(self):
        self.flow_history = defaultdict(list)
        self.conn_history = defaultdict(lambda: defaultdict(int))
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
    def analyze_flow(self, flow, protocol_name):
        """Analyze flow behavior and return behavior characteristics"""
        src_ip = flow.get('src_ip')
        dst_ip = flow.get('dst_ip')
        src_port = flow.get('src_port')
        dst_port = flow.get('dst_port')
        bytes_ = flow.get('bytes', 0)
        packets = flow.get('packets', 0)
        
        # Create connection key
        conn_key = f"{src_ip}:{dst_ip}"
        
        # Update connection history
        self.conn_history[conn_key]['bytes'] += bytes_
        self.conn_history[conn_key]['packets'] += packets
        self.conn_history[conn_key]['flows'] += 1
        
        # Perform cleanup if needed
        self._cleanup_old_data()
        
        # Analyze behavior
        behavior = {
            'type': self._determine_behavior_type(flow, protocol_name),
            'intensity': self._calculate_intensity(conn_key),
            'pattern': self._detect_pattern(conn_key),
            'risk_level': self._assess_risk(flow, protocol_name)
        }
        
        return behavior
    
    def _determine_behavior_type(self, flow, protocol_name):
        """Determine the type of behavior"""
        if protocol_name in ['HTTP2', 'QUIC']:
            return self._analyze_web_behavior(flow)
        elif protocol_name in ['DNS']:
            return self._analyze_dns_behavior(flow)
        elif protocol_name in ['MONGODB', 'REDIS', 'POSTGRESQL', 'MYSQL']:
            return self._analyze_database_behavior(flow)
        
        return 'NORMAL'
    
    def _analyze_web_behavior(self, flow):
        """Analyze web traffic behavior"""
        bytes_ = flow.get('bytes', 0)
        packets = flow.get('packets', 0)
        
        if bytes_ > 1000000:  # 1MB
            return 'BULK_TRANSFER'
        elif packets > 100 and bytes_ < 10000:
            return 'INTERACTIVE'
        elif packets == 1 and bytes_ < 100:
            return 'KEEPALIVE'
        
        return 'NORMAL'
    
    def _analyze_dns_behavior(self, flow):
        """Analyze DNS behavior"""
        bytes_ = flow.get('bytes', 0)
        
        if bytes_ > 4096:
            return 'DNS_LARGE_RESPONSE'
        elif bytes_ < 100:
            return 'DNS_QUERY'
        
        return 'DNS_NORMAL'
    
    def _analyze_database_behavior(self, flow):
        """Analyze database traffic behavior"""
        bytes_ = flow.get('bytes', 0)
        packets = flow.get('packets', 0)
        
        if bytes_ > 100000:
            return 'DB_BULK_OPERATION'
        elif packets > 50 and bytes_ < 5000:
            return 'DB_INTERACTIVE'
        
        return 'DB_NORMAL'
    
    def _calculate_intensity(self, conn_key):
        """Calculate traffic intensity"""
        history = self.conn_history[conn_key]
        
        if history['bytes'] > 10000000:  # 10MB
            return 'HIGH'
        elif history['bytes'] > 1000000:  # 1MB
            return 'MEDIUM'
        
        return 'LOW'
    
    def _detect_pattern(self, conn_key):
        """Detect traffic pattern"""
        history = self.conn_history[conn_key]
        
        if history['flows'] > 100:
            return 'SUSTAINED'
        elif history['flows'] > 10:
            return 'BURST'
        
        return 'SPORADIC'
    
    def _assess_risk(self, flow, protocol_name):
        """Assess risk level of the flow"""
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)
        bytes_ = flow.get('bytes', 0)
        
        risk_score = 0
        
        # Check for high-risk ports
        high_risk_ports = {22, 23, 3389, 5900}
        if src_port in high_risk_ports or dst_port in high_risk_ports:
            risk_score += 2
        
        # Check for unusual data sizes
        if bytes_ > 1000000:  # 1MB
            risk_score += 1
        
        # Protocol-based risk
        if protocol_name in ['TELNET', 'FTP']:
            risk_score += 2
        
        if risk_score >= 3:
            return 'HIGH'
        elif risk_score >= 1:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _cleanup_old_data(self):
        """Clean up old connection history"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            self.conn_history.clear()
            self.last_cleanup = current_time
