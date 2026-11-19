import pandas as pd
import streamlit as st
from twin_core import Gateway, train_twin, SENSORS, ATTACKER_IP

st.set_page_config(page_title="Digital Twin IDS - Online Simulation", layout="wide")


@st.cache_resource
def get_models():
    return train_twin()


def new_gateway():
    g = Gateway(get_models())
    for _ in range(30):          # warm-up: 30 normal steps
        g.tick()
    return g


if "gw" not in st.session_state:
    st.session_state.gw = new_gateway()
    st.session_state.msg = ""
gw = st.session_state.gw

st.title("Digital Twin Based IDS for Industrial IoT - Online Simulation")
st.caption("Sensors, network and attacker are SIMULATED inside this app (the attacker IP is a made-up "
           "address). The real project runs on two laptops over UDP. The detection logic is the same.")

with st.sidebar:
    st.header("Control panel")
    if st.button("Run 10 normal steps"):
        for _ in range(10):
            gw.tick()
        st.session_state.msg = ""
    st.divider()
    st.subheader("Launch an attack")
    kind_label = st.selectbox("Attack type", [
        "Fake sensor on a new IP (spoofing + tampering)",
        "New IP, believable value (spoofing only)",
        "Real sensor IP, wrong value (tampering only)"])
    sensor = st.selectbox("Sensor to attack", SENSORS)
    fake = st.slider("Fake value", 0.0, 120.0, 45.0)
    if st.button("Launch attack", type="primary"):
        kind = {0: "both", 1: "spoof", 2: "tamper"}[[
            "Fake sensor on a new IP (spoofing + tampering)",
            "New IP, believable value (spoofing only)",
            "Real sensor IP, wrong value (tampering only)"].index(kind_label)]
        out = gw.attack(kind, sensor, fake)
        dropped = out.count("DROPPED")
        st.session_state.msg = ("Attacker sent %d messages: first one caught as %s, %d dropped after blocking."
                                % (len(out), out[0], dropped)) if dropped else \
                               ("Attacker sent %d messages: %s (same IP as the sensor, so it cannot be blocked)."
                                % (len(out), out[0]))
    st.divider()
    if st.button("Reset simulation"):
        st.session_state.gw = new_gateway()
        st.session_state.msg = ""
        st.rerun()

df = gw.frame()
recent = df.tail(20)
bad = recent[recent.status != "NORMAL"]
attacks = df[df.status != "NORMAL"]
if len(bad) > 0:
    last = bad.iloc[-1]
    st.error("ATTACK DETECTED: %s on the %s sensor from IP %s" % (last.status, last.sensor, last.ip))
else:
    st.success("Factory is running normally")
if st.session_state.msg:
    st.info(st.session_state.msg)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Messages logged", len(df))
c2.metric("Attack events logged", len(attacks))
c3.metric("Blocked IPs", ", ".join(sorted(gw.blocked)) or "none")
c4.metric("Messages dropped", gw.dropped)

for s in SENSORS:
    st.subheader(s.capitalize() + ": real value vs twin expected")
    st.line_chart(df[df.sensor == s].tail(100)[["value", "expected"]].reset_index(drop=True))

st.subheader("Who attacked what")
if len(attacks):
    st.dataframe(attacks.groupby(["ip", "sensor", "status"]).size().reset_index(name="attack messages"))
else:
    st.write("No attacks yet. Use the control panel on the left.")
st.subheader("Latest attack events")
st.dataframe(attacks.tail(15).iloc[::-1])
st.caption("Limits: simulated data (not a real factory); a real attacker could hide behind a VPN.")