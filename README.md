# 🛡️ Snort IDS Lab – Detecting ICMP & Nmap Attacks  

> **Cybersecurity Lab Project** | By April Walker  
> 🎯 Goal: Deploy Snort as an Intrusion Detection System (IDS) and detect real attack traffic (pings + port scans) across a virtualized test network.

---

## 🌐 Lab Overview  
This project demonstrates how Snort can be configured to detect malicious or suspicious traffic inside a controlled virtual environment.  
I built a **3-VM lab** using VirtualBox:  

- **Ubuntu-Snort** → Running Snort IDS  
- **Kali Linux** → Attacker machine  
- **Windows 10** → Victim machine  

The IDS was configured to detect:  
- ✅ **ICMP pings** (ping sweeps / host discovery)  
- ✅ **TCP SYN scans** (Nmap port scans)  

---

## 🏗️ Lab Setup  

**Environment**  
- VirtualBox (with internal network `LAN10`)  
- Adapter1 (NAT) only when internet access was required (e.g. package downloads)  
- Adapter2 (Internal Network `LAN10`) for attack simulation  

**Tools Used**  
- [Snort 2.9.x](https://www.snort.org/) – IDS engine  
- Kali Linux – Attack tools (`ping`, `nmap`, `gobuster`)  
- Windows 10 – Victim host  
- Wireshark – Optional packet analysis  

---

## ⚙️ Configuration  

**Local Rules (`/etc/snort/rules/local.rules`)**  

```snort
# Alert on ICMP ping
alert icmp any any -> 192.168.10.0/24 any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)

# Alert on TCP SYN scans
alert tcp any any -> 192.168.10.0/24 any (flags:S; msg:"TCP Portscan Detected"; sid:1000002; rev:1;)
```

**Validate Snort Config**

```bash
sudo snort -T -c /etc/snort/snort.conf
```

**Run Snort in IDS Mode**

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
```

---

## 🚨 Attack Simulation
**1. ICMP Ping Detection**

From Windows Victim → Ping Snort:

```powershell
ping 192.168.10.10
```

Snort Console Ouput:

```CSS
[**] [1:1000001:1] ICMP Ping Detected [**]
```

![ICMP Alert](https://github.com/awalker816/snort-ids-lab/blob/0d3cd600bab954d4308e266d47e83bf631c8271d/screenshots/Snort-Windows%20Traffic.png)
### 🛰️ ICMP Ping Detection (Windows → Snort)

Windows Victim pinging the Snort sensor (`192.168.10.10`) while Snort logs the traffic in real time as **"ICMP Ping Detected"**.

---

**2. Nmap SYN Scan Detection**

From Kali Attacker → Run Nmap against Victim:

```bash
sudo nmap -sS -T4 -p 1-1000 192.168.10.30
```

Snort Console Output:

```CSS
[**] [1:1000002:1] TCP Portscan Detected [**]
```

![📸 Nmap output + Snort alert](https://github.com/awalker816/snort-ids-lab/blob/0d3cd600bab954d4308e266d47e83bf631c8271d/screenshots/nmap_alert.png)
### 🌐 ICMP Ping Sweep + Nmap Scan (Kali → Snort)

Kali Attacker running an ICMP ping sweep and Nmap host discovery across the subnet.  
Snort successfully triggered **"ICMP Ping Detected"** alerts in real time, confirming visibility of reconnaissance activity.

---

## 📊 Results

Successfully detected ICMP ping sweeps from both Kali + Windows

Successfully detected TCP SYN scans with Nmap

Config validated with Snort console alerts and optional (`.pcap`) logs

---

## 📂 Repository Structure

```plaintext
snort-ids-lab/
├── README.md
├── config/
│   ├── snort.conf
│   └── local.rules
├── screenshots/
│   ├── snort_running.png
│   ├── icmp_alert.png
│   ├── nmap_alert.png
│   └── wireshark_analysis.png
├── pcap/
│   └── portscan.pcap
└── docs/
    └── project_summary.pdf
```

---

## ⚙️ Configuration
**Local Rules (`/etc/snort/rules/local.rules`)**

```snort
# Alert on ICMP ping
alert icmp any any -> 192.168.10.0/24 any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)

# Alert on TCP SYN scans
alert tcp any any -> 192.168.10.0/24 any (flags:S; msg:"TCP Portscan Detected"; sid:1000002; rev:1;)
```

## 🚀 Next Steps

- Expand ruleset for HTTP bruteforce detection
  
- Integrate Snort with a SIEM (like Splunk or ELK)
  
- Automate detection lab with scripts or Ansible

---

## 💜 Closing Notes

This project reinforced my understanding of IDS fundamentals, rule writing, and packet analysis.
Snort caught the attacks in real-time, proving how valuable IDS can be in detecting early stages of reconnaissance.

✨ Branded for the journey:

#CyberBabeLoading #ThreatDetection #SnortIDS #BlueTeam
