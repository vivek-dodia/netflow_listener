# utils/flow_categorizer.py

class FlowCategorizer:
    # Size categories in bytes
    SIZE_CATEGORIES = {
        'tiny': 64,
        'small': 1024,
        'medium': 4096,
        'large': 65536,
        'huge': float('inf')
    }

    @staticmethod
    def categorize_size(bytes_count):
        """
        Categorize flow by size.
        Args:
            bytes_count: Number of bytes in flow
        Returns:
            str: Size category
        """
        try:
            bytes_count = int(bytes_count)
            for category, limit in FlowCategorizer.SIZE_CATEGORIES.items():
                if bytes_count < limit:
                    return category
            return 'huge'
        except Exception as e:
            print(f"Error categorizing flow size: {e}")
            return 'unknown'

    @staticmethod
    def determine_direction(dst_ip, server_ip='148.76.96.103'):
        """
        Determine flow direction relative to server.
        Args:
            dst_ip: Destination IP address
            server_ip: Server IP address to compare against
        Returns:
            str: 'inbound' or 'outbound'
        """
        try:
            return 'inbound' if dst_ip == server_ip else 'outbound'
        except Exception as e:
            print(f"Error determining flow direction: {e}")
            return 'unknown'

    @staticmethod
    def categorize_duration(duration_secs):
        """
        Categorize flow by duration.
        Args:
            duration_secs: Duration in seconds
        Returns:
            str: Duration category
        """
        try:
            if duration_secs < 1:
                return 'instant'
            elif duration_secs < 60:
                return 'short'
            elif duration_secs < 300:
                return 'medium'
            elif duration_secs < 3600:
                return 'long'
            else:
                return 'persistent'
        except Exception as e:
            print(f"Error categorizing duration: {e}")
            return 'unknown'
