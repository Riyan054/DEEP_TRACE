import os
import sys
import unittest
import numpy as np

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.ml.detector import AnomalyDetector

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector()

    def test_feature_extraction(self):
        # Sample packet dict
        pkt_dict = {
            "protocol": "TCP",
            "src_port": 443,
            "dst_port": 50000,
            "size": 1000,
            "ttl": 64,
            "flags": "SA",
            "payload_len": 960,
            "packet_rate": 5.0
        }
        
        features = self.detector.extract_features(pkt_dict)
        self.assertEqual(len(features), 8)
        self.assertEqual(features[0], 6.0) # TCP num
        self.assertEqual(features[1], 443.0) # src port
        self.assertEqual(features[2], 50000.0) # dst port
        self.assertEqual(features[3], 1000.0) # size
        self.assertEqual(features[4], 64.0) # ttl
        self.assertEqual(features[5], 18.0) # flags value (S=2 + A=16 = 18)
        self.assertEqual(features[6], 960.0) # payload length
        self.assertEqual(features[7], 5.0) # packet rate

    def test_bootstrap_dataset(self):
        X, y = self.detector.generate_synthetic_dataset()
        self.assertTrue(X.shape[0] > 1000)
        self.assertEqual(X.shape[1], 8)
        self.assertEqual(len(y), X.shape[0])

    def test_prediction_fallback(self):
        # Test signature based check
        dos_pkt = {
            "protocol": "TCP",
            "src_port": 1234,
            "dst_port": 80,
            "size": 64,
            "ttl": 64,
            "flags": "S",
            "payload_len": 0,
            "packet_rate": 300.0 # High rate
        }
        
        is_anomaly, score, reason = self.detector._fallback_rule_based_check(dos_pkt)
        self.assertTrue(is_anomaly)
        self.assertEqual(reason, "DoS")

if __name__ == "__main__":
    unittest.main()
