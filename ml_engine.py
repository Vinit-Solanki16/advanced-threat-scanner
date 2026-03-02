import numpy as np
import requests
import time
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.response_times = []
        self.response_sizes = []
        self.model = IsolationForest(contamination=0.1)  # Expect 10% anomalies
        self.is_trained = False

    def learn_baseline(self, num_samples=20):
        """
        Sends normal requests to learn the server's 'heartbeat'.
        Measures Latency (Time) and Response Size (Bytes).
        """
        print(f"    [ML] Learning baseline behavior ({num_samples} samples)...")
        
        for i in range(num_samples):
            try:
                start = time.time()
                # We add a random parameter to avoid caching
                requests.get(self.target_url, params={"cache_buster": i}, timeout=5)
                latency = time.time() - start
                
                # We record the latency. 
                # (In a real app, we'd also record content-length, status code, etc.)
                self.response_times.append([latency])
                
            except requests.exceptions.RequestException:
                pass
                
        # Train the Isolation Forest Model
        if len(self.response_times) > 5:
            self.model.fit(self.response_times)
            self.is_trained = True
            print("    [ML] Model Trained. Ready to detect anomalies.")
        else:
            print("    [!] Not enough data to train ML model.")

    def check_anomaly(self, response_time):
        """
        Predicts if a specific response time is an 'outlier' (potential vulnerability).
        Returns: True if anomalous, False if normal.
        """
        if not self.is_trained:
            return False
            
        # Reshape data for sklearn
        data = np.array([[response_time]])
        
        # predict() returns -1 for outlier, 1 for inlier
        prediction = self.model.predict(data)
        
        if prediction[0] == -1:
            return True
        return False
