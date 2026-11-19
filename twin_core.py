"""Core logic of the Digital Twin IDS (simulated sensors, no network)."""
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression

SENSOR_IP = "192.168.1.10"     # simulated address of the factory sensors
ATTACKER_IP = "192.168.1.50"   # simulated address of the attacker
SENSORS = ["temperature", "pressure", "vibration"]


def train_twin():
    """Train the twin on 500 normal simulated readings (same formulas as the project)."""
    tn = np.arange(500)
    rng = np.random.RandomState(0)
    sp = 1500 + 300 * np.sin(2 * np.pi * tn / 100) + rng.normal(0, 10, 500)
    tt = 40 + 0.02 * sp + rng.normal(0, 0.5, 500)
    pp = 10 + 0.01 * sp + rng.normal(0, 0.3, 500)
    vv = 0.5 + 0.001 * sp + rng.normal(0, 0.05, 500)
    X = sp.reshape(-1, 1)
    models = {}
    for name, y in [("temperature", tt), ("pressure", pp), ("vibration", vv)]:
        m = LinearRegression().fit(X, y)
        models[name] = (m, 4 * (y - m.predict(X)).std())   # limit = 4 x normal error spread
    return models


class Gateway:
    def __init__(self, models, seed=2):
        self.models = models
        self.rng = np.random.RandomState(seed)
        self.t = 0
        self.speed = 1500.0
        self.trusted = {}      # sensor -> first IP seen
        self.blocked = set()
        self.dropped = 0
        self.rows = []         # logged events

    def expected(self, sensor):
        return float(self.models[sensor][0].predict([[self.speed]])[0])

    def receive(self, ip, sensor, value, clock):
        """Process one message. Returns the status, or 'DROPPED' for a blocked IP."""
        if ip in self.blocked:
            self.dropped += 1
            return "DROPPED"
        self.trusted.setdefault(sensor, ip)
        ip_ok = self.trusted[sensor] == ip
        if sensor == "speed":
            expected, limit = value, 1e9
        else:
            expected = self.expected(sensor)
            limit = self.models[sensor][1]
        value_ok = abs(value - expected) <= limit
        if ip_ok and value_ok:
            status = "NORMAL"
        elif value_ok:
            status = "SPOOFING"
        elif ip_ok:
            status = "TAMPERING"
        else:
            status = "SPOOFING+TAMPERING"
        if sensor == "speed" and ip_ok:
            self.speed = value
        self.rows.append(dict(time=clock, ip=ip, sensor=sensor, value=round(value, 2),
                              expected=round(expected, 2), status=status))
        if status != "NORMAL" and not ip_ok and ip not in self.trusted.values():
            self.blocked.add(ip)
        return status

    def tick(self):
        """One normal step: the four sensors each send one reading."""
        self.t += 1
        clock = "t=%d" % self.t
        sp = 1500 + 300 * np.sin(2 * np.pi * self.t / 100) + self.rng.normal(0, 10)
        self.receive(SENSOR_IP, "speed", float(sp), clock)
        true = {"temperature": 40 + 0.02 * sp + self.rng.normal(0, 0.5),
                "pressure": 10 + 0.01 * sp + self.rng.normal(0, 0.3),
                "vibration": 0.5 + 0.001 * sp + self.rng.normal(0, 0.05)}
        for s in SENSORS:
            self.receive(SENSOR_IP, s, float(true[s]), clock)

    def attack(self, kind, sensor, fake_value, n=10):
        """Attacker sends n messages. Returns the list of statuses."""
        clock = "t=%d" % self.t
        ip = SENSOR_IP if kind == "tamper" else ATTACKER_IP
        out = []
        for _ in range(n):
            if kind == "spoof":      # new IP, believable value
                v = self.expected(sensor)
            else:                    # wrong value
                v = fake_value
            out.append(self.receive(ip, sensor, v, clock))
        return out

    def frame(self):
        return pd.DataFrame(self.rows, columns=["time", "ip", "sensor", "value", "expected", "status"])