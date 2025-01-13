from prometheus_client import Gauge

class NetFlowMetrics:
    def __init__(self):
        self.bytes_total = Gauge('netflow_bytes_total', 'Total bytes processed')
        self.packets_total = Gauge('netflow_packets_total', 'Total packets processed')
        self.active_flows = Gauge('netflow_active_flows', 'Number of active flows')
        
    def update_metrics(self, flow):
        if flow:
            self.bytes_total.inc(flow.get('bytes', 0))
            self.packets_total.inc(flow.get('packets', 0))
