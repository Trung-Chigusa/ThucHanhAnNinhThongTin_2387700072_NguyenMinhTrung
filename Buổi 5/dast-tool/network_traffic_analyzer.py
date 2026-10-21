"""Read aggregate interface counters; packet contents are never captured."""

import psutil


class NetworkTrafficAnalyzer:
    def get_network_stats(self):
        counters = psutil.net_io_counters(pernic=True) or {}
        return {
            name: {
                "bytes_sent": value.bytes_sent,
                "bytes_recv": value.bytes_recv,
                "packets_sent": value.packets_sent,
                "packets_recv": value.packets_recv,
                "errin": value.errin,
                "errout": value.errout,
                "dropin": value.dropin,
                "dropout": value.dropout,
            }
            for name, value in sorted(counters.items())
        }
