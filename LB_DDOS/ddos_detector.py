import numpy as np
import joblib
import time
from collections import defaultdict


def ip_to_int(ip):
    return sum([int(x) << (8*i) for i, x in enumerate(ip.split('.')[::-1])])


class DDoSDetector:
    def __init__(self, model_path=None):
        self.model = joblib.load(model_path) if model_path else None

        # Flow tracking: (src_ip, src_port) → stats
        self.flows = defaultdict(lambda: {
            'start_time': time.time(),
            'packet_count': 0,
            'byte_count': 0
        })

    # ─────────────────────────────────────
    # RECORD FLOW
    # ─────────────────────────────────────
    def record(self, src_ip, src_port, dst_ip, dst_port,
           proto, pkt_size, flags):

        key = (src_ip, src_port, dst_ip, dst_port, proto)
        f = self.flows[key]

        # reset flow sau 10s
        if time.time() - f['start_time'] > 10:
            self.flows[key] = {
                'start_time': time.time(),
                'packet_count': 1,
                'byte_count': pkt_size
            }
            return

        f['packet_count'] += 1
        f['byte_count'] += pkt_size

    # ─────────────────────────────────────
    # EXTRACT 18 FEATURES
    # ─────────────────────────────────────
    def extract_features(self, src_ip, src_port, dst_ip,
                     dst_port, proto, flags):

        key = (src_ip, src_port, dst_ip, dst_port, proto)
        f = self.flows[key]

        now = time.time()
        duration = max(now - f['start_time'], 1e-6)

        pkt_count = f['packet_count']
        byte_count = f['byte_count']

        pkt_rate = pkt_count / duration
        byte_rate = byte_count / duration

        return np.array([[ 
            ip_to_int(src_ip),
            src_port,
            ip_to_int(dst_ip),
            dst_port,
            proto,
            0,
            0,
            int(duration),
            int((duration % 1)*1e9),
            30,
            60,
            int(flags),
            pkt_count,
            byte_count,
            pkt_rate,
            pkt_rate / 1e9,
            byte_rate,
            byte_rate / 1e9
        ]])
    # ─────────────────────────────────────
    # PREDICT
    # ─────────────────────────────────────
    def is_attack(self, src_ip, src_port, dst_ip,
                  dst_port, proto, flags):

        features = self.extract_features(
            src_ip, src_port, dst_ip, dst_port, proto, flags
        )

        pred = self.model.predict(features)[0]
        return bool(pred == 1)