# 5G QoS and Multi-Plane Anomaly Monitoring Dashboard

A Python-based monitoring dashboard for analyzing network traffic and monitoring Quality of Service (QoS) parameters in a simulated 5G Core environment.

The project combines real-time packet capture using Scapy with simulated AMF, SMF, and UPF metrics and uses statistical Z-score analysis to identify abnormal network behavior.

---

## 📌 Project Overview

5G networks generate a large amount of network traffic that needs to be monitored for performance and abnormal behavior.

This project provides an interactive dashboard that:

- Captures network packets using Scapy
- Identifies common network protocols
- Detects GTP-U traffic using UDP port 2152
- Monitors latency, jitter, and throughput
- Simulates AMF, SMF, and UPF network metrics
- Simulates different network attack/load scenarios
- Detects abnormal behavior using Z-score analysis
- Displays real-time network statistics and anomaly events
- Provides an interactive Streamlit-based monitoring interface

> **Note:** The packet capture portion uses real network traffic, while the AMF, SMF, UPF behavior and attack scenarios are simulated for demonstration and monitoring purposes.

---

## 🎯 Objectives

The main objectives of this project are:

1. Monitor network packet traffic in real time.
2. Analyze important QoS parameters.
3. Identify different network protocols.
4. Detect GTP-U traffic associated with the 5G user plane.
5. Simulate 5G Core network functions.
6. Detect abnormal network behavior using statistical analysis.
7. Provide an easy-to-use monitoring dashboard.

---

## 🚀 Key Features

### 1. Real-Time Packet Capture

The project uses Scapy to capture network packets.

Captured packets are processed to extract useful information such as:

- Packet count
- Packet size
- Packet timing
- Protocol type

---

### 2. QoS Monitoring

The dashboard monitors important network Quality of Service parameters.

#### Latency

Measures the time difference between consecutive packets.

#### Jitter

Measures variation in packet delay.

#### Throughput

Estimates traffic volume based on captured packet sizes.

These metrics help understand the behavior and performance of network traffic.

---

### 3. Protocol Detection

The system identifies different protocols including:

- TCP
- UDP
- ICMP
- GTP-U
- Other traffic

GTP-U traffic is identified when UDP source or destination port `2152` is detected.

---

### 4. 5G Core Network Simulation

The project represents important 5G Core functions:

### AMF - Access and Mobility Management Function

Responsible for control-plane activities such as:

- User registration
- Connection management
- Mobility management

### SMF - Session Management Function

Responsible for:

- Session establishment
- Session management
- Session-related control

### UPF - User Plane Function

Responsible for forwarding user-plane traffic.

The project simulates load values for these functions to demonstrate monitoring and anomaly detection.

---

## 🔍 Anomaly Detection

The project uses a statistical **Z-score based anomaly detection approach**.

The Z-score measures how far a new observation is from the historical average in terms of standard deviations.

### Formula

```text
Z = |x - μ| / σ
