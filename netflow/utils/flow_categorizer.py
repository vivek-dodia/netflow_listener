class FlowCategorizer:
    def categorize_flow(self, flow):
        if not flow:
            return 'Unknown'
            
        protocol = flow.get('protocol', 0)
        if protocol == 6:  # TCP
            return 'TCP'
        elif protocol == 17:  # UDP
            return 'UDP'
        elif protocol == 1:  # ICMP
            return 'ICMP'
        else:
            return 'Other'
