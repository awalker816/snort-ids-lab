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

From Windows Victim → Ping Snort + Snort Console Ouput:

#screenshot
