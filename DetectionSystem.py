from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionSystem:
    def __init__(self):
        self.anomalyDetector = IsolationForest(contamination=0.1, random_state=42)
        self.signRules = self.loadSignRules()
        self.training_data = []

    def loadSignRules(self):
        return{'syn_flood': {'condition': lambda features: (features['tcpFlags'] == 2 and features['packetRate'] > 100)},
               'portScan': {'condition': lambda features: (features['packetSize'] < 100 and features['packetSize'] > 50)}}

    def train_anamolyDetector(self, normalTrafficData):
        self.anomalyDetector.fit(normalTrafficData)

    def detectThreats(self, features):
        threats = []

        #signature based detection
        for ruleName, rule in self.signRules.itmes():
            if rule['condtiion'](features):
                threats.append({'type': 'signature', 'rule': ruleName, 'confidence': 1.0})

        #anamoly based detection
        featureVector = np.array([[
            features['packetSize'],
            features['packetRate'],
            features['byteRate']
        ]])
        score = self.anomalyDetector.score_samples(featureVector)[0]
        if score < -0.5:
            threats.append({
                'type': 'anamoly',
                'score': score,
                'confidence': min(1.0, abs(score))
            })
        return threats