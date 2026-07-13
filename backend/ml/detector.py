import os
import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from backend.utils.config import MODEL_DIR, ACTIVE_MODEL

class AnomalyDetector:
    def __init__(self):
        self.active_model_name = ACTIVE_MODEL
        self.models = {}
        self.metrics = {}
        self.is_trained = {}
        
        # Initialize default state
        for name in ["Isolation Forest", "Random Forest", "One-Class SVM"]:
            self.is_trained[name] = False
            self.metrics[name] = {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "training_time": 0.0,
                "trained_at": 0.0,
                "samples_count": 0
            }
            
        # Try to load existing models from disk
        self.load_all_models()

    def extract_features(self, pkt: Any) -> List[float]:
        """
        Extract a numerical feature vector from a packet database model, dict, or scapy packet.
        Features:
        1. Protocol (TCP=6, UDP=17, ICMP=1, ARP=2, Other=0)
        2. Source Port (0 if not TCP/UDP)
        3. Destination Port (0 if not TCP/UDP)
        4. Size (total length)
        5. TTL (0 if none)
        6. TCP Flags (decimal equivalent of flag byte: S=2, A=16, F=1, R=4, P=8, etc.)
        7. Payload Length
        8. Packet Rate (packets/sec - computed dynamically or estimated from payload size)
        """
        # Default features
        protocol_num = 0
        src_port = 0
        dst_port = 0
        size = 64
        ttl = 64
        flags_num = 0
        payload_len = 0
        packet_rate = 10.0

        if isinstance(pkt, dict):
            proto = str(pkt.get("protocol", "")).upper()
            if "TCP" in proto:
                protocol_num = 6
            elif "UDP" in proto:
                protocol_num = 17
            elif "ICMP" in proto:
                protocol_num = 1
            elif "ARP" in proto:
                protocol_num = 2
            
            src_port = pkt.get("src_port") or 0
            dst_port = pkt.get("dst_port") or 0
            size = pkt.get("size") or 64
            ttl = pkt.get("ttl") or 64
            flags_str = pkt.get("flags") or ""
            payload_len = pkt.get("payload_len") or 0
            packet_rate = pkt.get("packet_rate") or 10.0
            
            # Map flags string to number
            # F=1, S=2, R=4, P=8, A=16, U=32
            for char in flags_str:
                if char == 'F': flags_num += 1
                elif char == 'S': flags_num += 2
                elif char == 'R': flags_num += 4
                elif char == 'P': flags_num += 8
                elif char == 'A': flags_num += 16
                elif char == 'U': flags_num += 32
        else:
            # Assume it's a database Packet model object
            proto = str(getattr(pkt, "protocol", "")).upper()
            if "TCP" in proto:
                protocol_num = 6
            elif "UDP" in proto:
                protocol_num = 17
            elif "ICMP" in proto:
                protocol_num = 1
            elif "ARP" in proto:
                protocol_num = 2

            src_port = getattr(pkt, "src_port", None) or 0
            dst_port = getattr(pkt, "dst_port", None) or 0
            size = getattr(pkt, "size", 64)
            ttl = getattr(pkt, "ttl", 64)
            flags_str = getattr(pkt, "flags", "") or ""
            payload_len = getattr(pkt, "payload_len", 0)
            
            # Parse flags
            for char in flags_str:
                if char == 'F': flags_num += 1
                elif char == 'S': flags_num += 2
                elif char == 'R': flags_num += 4
                elif char == 'P': flags_num += 8
                elif char == 'A': flags_num += 16
                elif char == 'U': flags_num += 32

            # Simulate estimation of packet rate based on ports/size if not tracked
            packet_rate = getattr(pkt, "anomaly_score", 10.0)  # Borrowing score slot for feature loading

        return [
            float(protocol_num),
            float(src_port),
            float(dst_port),
            float(size),
            float(ttl),
            float(flags_num),
            float(payload_len),
            float(packet_rate)
        ]

    def generate_synthetic_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate a bootstrap dataset containing normal and anomalous packet vectors
        for initial model training.
        """
        np.random.seed(42)
        X = []
        y = []

        # 1. Generate Normal Traffic (approx 1200 packets)
        # Normal web requests (HTTP/HTTPS)
        for _ in range(800):
            proto = 6  # TCP
            sport = np.random.randint(49152, 65535)
            dport = np.random.choice([80, 443])
            size = np.random.randint(100, 1500)
            ttl = np.random.choice([64, 128])
            flags = np.random.choice([16, 24])  # ACK, PSH-ACK
            plen = max(0, size - 40)
            rate = np.random.uniform(1.0, 15.0)
            X.append([proto, sport, dport, size, ttl, flags, plen, rate])
            y.append(0)

        # Normal DNS requests
        for _ in range(400):
            proto = 17  # UDP
            sport = np.random.randint(49152, 65535)
            dport = 53
            size = np.random.randint(60, 200)
            ttl = 64
            flags = 0
            plen = size - 28
            rate = np.random.uniform(0.5, 5.0)
            X.append([proto, sport, dport, size, ttl, flags, plen, rate])
            y.append(0)

        # 2. Generate Anomalous Traffic (approx 300 packets)
        # Port Scan (TCP SYN to many different ports, low payload, high rate)
        for _ in range(100):
            proto = 6
            sport = np.random.randint(1024, 65535)
            dport = np.random.choice([21, 22, 23, 25, 80, 443, 445, 8080, 3306])
            size = 64
            ttl = 64
            flags = 2  # SYN
            plen = 0
            rate = np.random.uniform(80.0, 200.0)
            X.append([proto, sport, dport, size, ttl, flags, plen, rate])
            y.append(1)

        # DoS Attack (Flood of UDP or TCP packets to single port, high rate)
        for _ in range(100):
            proto = np.random.choice([6, 17])
            sport = np.random.randint(1024, 65535)
            dport = 80
            size = np.random.randint(64, 1000)
            ttl = 64
            flags = np.random.choice([2, 0])  # SYN or none
            plen = size - 40
            rate = np.random.uniform(250.0, 500.0)  # Flood rate
            X.append([proto, sport, dport, size, ttl, flags, plen, rate])
            y.append(1)

        # Exfiltration / Large Payload anomaly
        for _ in range(100):
            proto = 6
            sport = np.random.choice([80, 443])
            dport = np.random.randint(49152, 65535)
            size = np.random.randint(3000, 65000)  # Oversized packets
            ttl = 128
            flags = 24  # PSH-ACK
            plen = size - 40
            rate = np.random.uniform(5.0, 20.0)
            X.append([proto, sport, dport, size, ttl, flags, plen, rate])
            y.append(1)

        return np.array(X), np.array(y)

    def train_all(self) -> Dict[str, Any]:
        """
        Train all models on synthetic baseline traffic, compute performance metrics,
        and save them to disk.
        """
        X, y = self.generate_synthetic_dataset()
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # 1. Train Random Forest (Supervised)
        t0 = time.time()
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        rf_time = time.time() - t0
        rf_preds = rf.predict(X_test)
        
        self.models["Random Forest"] = rf
        self.is_trained["Random Forest"] = True
        self.metrics["Random Forest"] = {
            "accuracy": float(accuracy_score(y_test, rf_preds)),
            "precision": float(precision_score(y_test, rf_preds, zero_division=0)),
            "recall": float(recall_score(y_test, rf_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, rf_preds, zero_division=0)),
            "training_time": float(rf_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train)
        }
        self.save_model("Random Forest", rf, self.metrics["Random Forest"])

        # 2. Train Isolation Forest (Unsupervised - train on normal packets only)
        X_train_normal = X_train[y_train == 0]
        t0 = time.time()
        if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        if_model.fit(X_train_normal)
        if_time = time.time() - t0
        
        # Evaluate: Isolation Forest returns -1 for anomalies, 1 for normal
        if_preds_raw = if_model.predict(X_test)
        if_preds = np.where(if_preds_raw == -1, 1, 0)  # Map to 0 (normal), 1 (anomaly)
        
        self.models["Isolation Forest"] = if_model
        self.is_trained["Isolation Forest"] = True
        self.metrics["Isolation Forest"] = {
            "accuracy": float(accuracy_score(y_test, if_preds)),
            "precision": float(precision_score(y_test, if_preds, zero_division=0)),
            "recall": float(recall_score(y_test, if_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, if_preds, zero_division=0)),
            "training_time": float(if_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train_normal)
        }
        self.save_model("Isolation Forest", if_model, self.metrics["Isolation Forest"])

        # 3. Train One-Class SVM (Unsupervised - train on normal packets only)
        t0 = time.time()
        svm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
        svm.fit(X_train_normal)
        svm_time = time.time() - t0
        
        # Evaluate: returns -1 for anomalies, 1 for normal
        svm_preds_raw = svm.predict(X_test)
        svm_preds = np.where(svm_preds_raw == -1, 1, 0)
        
        self.models["One-Class SVM"] = svm
        self.is_trained["One-Class SVM"] = True
        self.metrics["One-Class SVM"] = {
            "accuracy": float(accuracy_score(y_test, svm_preds)),
            "precision": float(precision_score(y_test, svm_preds, zero_division=0)),
            "recall": float(recall_score(y_test, svm_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, svm_preds, zero_division=0)),
            "training_time": float(svm_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train_normal)
        }
        self.save_model("One-Class SVM", svm, self.metrics["One-Class SVM"])

        return self.get_comparison_data()

    def save_model(self, name: str, model_obj: Any, metrics: Dict[str, Any]):
        """Save trained model file and corresponding metrics JSON."""
        safe_name = name.replace(" ", "_").lower()
        model_path = os.path.join(MODEL_DIR, f"{safe_name}.joblib")
        meta_path = os.path.join(MODEL_DIR, f"{safe_name}_meta.joblib")
        
        try:
            joblib.dump(model_obj, model_path)
            joblib.dump(metrics, meta_path)
        except Exception as e:
            print(f"Error saving ML model {name}: {e}")

    def load_all_models(self):
        """Loads all saved models from disk if they exist, otherwise triggers bootstrapping."""
        models_found = False
        for name in ["Isolation Forest", "Random Forest", "One-Class SVM"]:
            safe_name = name.replace(" ", "_").lower()
            model_path = os.path.join(MODEL_DIR, f"{safe_name}.joblib")
            meta_path = os.path.join(MODEL_DIR, f"{safe_name}_meta.joblib")
            
            if os.path.exists(model_path) and os.path.exists(meta_path):
                try:
                    self.models[name] = joblib.load(model_path)
                    self.metrics[name] = joblib.load(meta_path)
                    self.is_trained[name] = True
                    models_found = True
                except Exception as e:
                    print(f"Error loading model {name}: {e}")
                    self.is_trained[name] = False

        if not models_found:
            print("No pre-trained ML models found. Bootstrapping initial training...")
            try:
                self.train_all()
            except Exception as e:
                print(f"Error bootstrapping models: {e}")

    def predict(self, pkt_data: Any) -> Tuple[bool, float, str]:
        """
        Run inference using the active ML model on the packet features.
        Returns: (is_anomaly, anomaly_score, reason)
        """
        model_name = self.active_model_name
        
        # If model is not trained or loaded, fallback to basic rule-based profiling
        if not self.is_trained.get(model_name) or model_name not in self.models:
            return self._fallback_rule_based_check(pkt_data)
        
        try:
            model = self.models[model_name]
            features = np.array([self.extract_features(pkt_data)])
            
            # Prediction logic based on model type
            if model_name == "Random Forest":
                pred = int(model.predict(features)[0])
                # Use probability as score
                probs = model.predict_proba(features)[0]
                score = float(probs[1]) if len(probs) > 1 else 0.0
            elif model_name == "Isolation Forest":
                raw_pred = model.predict(features)[0]
                pred = 1 if raw_pred == -1 else 0
                # Map raw score to range 0.0 - 1.0 (lower is more anomalous in scikit-learn, score_samples is negative)
                raw_score = model.score_samples(features)[0]
                score = float(np.clip(-raw_score, 0.0, 1.0))
            elif model_name == "One-Class SVM":
                raw_pred = model.predict(features)[0]
                pred = 1 if raw_pred == -1 else 0
                # Use distance to decision boundary
                dist = model.decision_function(features)[0]
                score = float(np.clip(1.0 / (1.0 + np.exp(dist)), 0.0, 1.0))
            else:
                return self._fallback_rule_based_check(pkt_data)

            is_anomaly = bool(pred == 1)
            reason = None
            if is_anomaly:
                reason = self._infer_anomaly_reason(pkt_data)
                
            return is_anomaly, score, reason

        except Exception as e:
            print(f"Prediction failed with {model_name}, reverting to rule checking: {e}")
            return self._fallback_rule_based_check(pkt_data)

    def _fallback_rule_based_check(self, pkt: Any) -> Tuple[bool, float, str]:
        """Simple signature-based analyzer for fallback or when models aren't ready."""
        size = 0
        flags = ""
        payload_len = 0
        dst_port = 0
        rate = 10.0

        if isinstance(pkt, dict):
            size = pkt.get("size") or 0
            flags = pkt.get("flags") or ""
            payload_len = pkt.get("payload_len") or 0
            dst_port = pkt.get("dst_port") or 0
            rate = pkt.get("packet_rate") or 10.0
        else:
            size = getattr(pkt, "size", 0)
            flags = getattr(pkt, "flags", "") or ""
            payload_len = getattr(pkt, "payload_len", 0)
            dst_port = getattr(pkt, "dst_port", 0) or 0
            rate = getattr(pkt, "anomaly_score", 10.0)

        # Check for malformed pack
        if size > 65535 or size < 20:
            return True, 0.9, "Malformed Packet"
        # Check Large payload
        if size > 1500:
            return True, 0.75, "Large Payload"
        # Port scan signature (syn packets to standard sensitive ports at high rate)
        if "S" in flags and dst_port in [21, 22, 23, 135, 139, 445] and rate > 50:
            return True, 0.85, "Port Scan"
        # DoS check
        if rate > 200:
            return True, 0.95, "DoS"
        
        return False, 0.0, None

    def _infer_anomaly_reason(self, pkt: Any) -> str:
        """Heuristics to assign readable labels to anomalies flagged by ML models."""
        size = 0
        flags = ""
        payload_len = 0
        dst_port = 0
        rate = 10.0
        proto = ""

        if isinstance(pkt, dict):
            size = pkt.get("size") or 0
            flags = pkt.get("flags") or ""
            payload_len = pkt.get("payload_len") or 0
            dst_port = pkt.get("dst_port") or 0
            rate = pkt.get("packet_rate") or 10.0
            proto = str(pkt.get("protocol", "")).upper()
        else:
            size = getattr(pkt, "size", 0)
            flags = getattr(pkt, "flags", "") or ""
            payload_len = getattr(pkt, "payload_len", 0)
            dst_port = getattr(pkt, "dst_port", 0) or 0
            rate = getattr(pkt, "anomaly_score", 10.0)
            proto = str(getattr(pkt, "protocol", "")).upper()

        if rate > 100:
            return "DoS"
        if "S" in flags and dst_port in [21, 22, 23, 445, 3389]:
            return "Port Scan"
        if size > 1500:
            return "Large Payload"
        if size < 20 or size > 65535:
            return "Malformed Packet"
        if proto not in ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"]:
            return "Unknown Protocol"
        
        return "Abnormal Packet Rate"

    def get_comparison_data(self) -> Dict[str, Any]:
        """Format metrics for all models to be displayed side-by-side in the dashboard."""
        return {
            "models": [
                {
                    "model_name": name,
                    "accuracy": self.metrics[name]["accuracy"],
                    "precision": self.metrics[name]["precision"],
                    "recall": self.metrics[name]["recall"],
                    "f1_score": self.metrics[name]["f1_score"],
                    "training_time": self.metrics[name]["training_time"],
                    "trained_at": self.metrics[name]["trained_at"],
                    "samples_count": self.metrics[name]["samples_count"]
                }
                for name in ["Isolation Forest", "Random Forest", "One-Class SVM"]
            ],
            "active_model": self.active_model_name
        }

    def set_active_model(self, model_name: str):
        """Changes the active model selection."""
        if model_name in self.metrics:
            self.active_model_name = model_name
            return True
        return False

    def retrain_from_packets(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Retrain models using packet vectors extracted from database.
        Fallbacks to synthetic training if insufficient packet count.
        """
        if len(packets) < 50:
            # Revert to synthetic data generation to guarantee robust behavior
            return self.train_all()

        # Extract features and tags
        X = []
        y = []
        for p in packets:
            X.append(self.extract_features(p))
            # Binary label: 1 if user marked or rule classified as Suspicious/Dangerous, 0 otherwise
            y.append(1 if getattr(p, "is_anomaly", False) or getattr(p, "severity", "Safe") != "Safe" else 0)
            
        X = np.array(X)
        y = np.array(y)

        # Check classes distribution. If we only have 1 class, inject mock anomalies to prevent RF failure
        if len(np.unique(y)) < 2:
            mock_x, mock_y = self.generate_synthetic_dataset()
            X = np.vstack([X, mock_x[:100]])
            y = np.concatenate([y, mock_y[:100]])

        # Train/Test split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # 1. Random Forest
        t0 = time.time()
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        rf_time = time.time() - t0
        rf_preds = rf.predict(X_test)
        
        self.models["Random Forest"] = rf
        self.is_trained["Random Forest"] = True
        self.metrics["Random Forest"] = {
            "accuracy": float(accuracy_score(y_test, rf_preds)),
            "precision": float(precision_score(y_test, rf_preds, zero_division=0)),
            "recall": float(recall_score(y_test, rf_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, rf_preds, zero_division=0)),
            "training_time": float(rf_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train)
        }
        self.save_model("Random Forest", rf, self.metrics["Random Forest"])

        # 2. Isolation Forest
        X_train_normal = X_train[y_train == 0]
        if len(X_train_normal) < 10:
            X_train_normal = X_train  # Fallback if normal data is sparse
        t0 = time.time()
        if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        if_model.fit(X_train_normal)
        if_time = time.time() - t0
        if_preds_raw = if_model.predict(X_test)
        if_preds = np.where(if_preds_raw == -1, 1, 0)
        
        self.models["Isolation Forest"] = if_model
        self.is_trained["Isolation Forest"] = True
        self.metrics["Isolation Forest"] = {
            "accuracy": float(accuracy_score(y_test, if_preds)),
            "precision": float(precision_score(y_test, if_preds, zero_division=0)),
            "recall": float(recall_score(y_test, if_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, if_preds, zero_division=0)),
            "training_time": float(if_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train_normal)
        }
        self.save_model("Isolation Forest", if_model, self.metrics["Isolation Forest"])

        # 3. One-Class SVM
        t0 = time.time()
        svm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
        svm.fit(X_train_normal)
        svm_time = time.time() - t0
        svm_preds_raw = svm.predict(X_test)
        svm_preds = np.where(svm_preds_raw == -1, 1, 0)
        
        self.models["One-Class SVM"] = svm
        self.is_trained["One-Class SVM"] = True
        self.metrics["One-Class SVM"] = {
            "accuracy": float(accuracy_score(y_test, svm_preds)),
            "precision": float(precision_score(y_test, svm_preds, zero_division=0)),
            "recall": float(recall_score(y_test, svm_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, svm_preds, zero_division=0)),
            "training_time": float(svm_time),
            "trained_at": float(time.time()),
            "samples_count": len(X_train_normal)
        }
        self.save_model("One-Class SVM", svm, self.metrics["One-Class SVM"])

        return self.get_comparison_data()
