# 🔍 Network Port Scanner - GUI Tool

A simple, visual tool to check which network ports are open or closed on any computer or server. Built with Python's built-in libraries – **no installation needed**!

Perfect for beginners learning networking, cybersecurity, or Python GUI development.

---

## 🎯 What This Tool Does

Think of it as a "digital doorknob tester":
- You give it an address (like `127.0.0.1` or `google.com`)
- It checks each port number (like doors 1 through 100)
- Green = **OPEN** (someone is listening)
- Red = **CLOSED** (nobody there)

**Safe for learning**: Only scans what you tell it to – respects firewalls and won't hack anything.

---

## ✨ Features

✅ **Visual GUI** – No command line needed  
✅ **Real-time results** – See ports as they're scanned  
✅ **Progress bar + timer** – Know exactly how long it takes  
✅ **Stop button** – Cancel long scans anytime  
✅ **Save reports** – Auto-saves to Desktop with timestamp  
✅ **Educational hints** – Tells you what each port does  
✅ **Threaded scanning** – Window never freezes  
✅ **Zero dependencies** – Uses only Python built-in libraries  

---

## 🚀 Quick Start (2 Minutes)

### Step 1: Save the Code
Copy `port_scanner.py` and save it to your Desktop or any folder.

### Step 2: Run It
**Windows**: Double-click the file  
**Mac/Linux**: Open terminal, type `python3 port_scanner.py`

The window will pop up immediately.

### Step 3: Your First Scan
1. Leave **Host/IP** as `127.0.0.1` (your own computer)
2. Click the **"📋 Common Ports"** button
3. Click **"▶ START SCAN"**
4. Watch the results appear in real-time!

---

## 📊 Understanding Your Results

### **Color Codes**
- **🟢 GREEN (OPEN)** → A program is actively using this port
- **🔴 RED (Closed)** → Port is not in use (normal)
- **⚠ ORANGE (Error)** → Network issue or firewall blocked it

### **What You'll See on Your PC (127.0.0.1)**

| Port | Why It's Usually Open/Closed |
|------|------------------------------|
| **80, 443** | **OPEN** only if you're running a web server (XAMPP, IIS) |
| **135-139, 445** | **MAYBE OPEN** on Windows (file sharing) |
| **3389** | **OPEN** if Remote Desktop is enabled |
| **21, 23, 25** | **CLOSED** (old, insecure services) |
| **3306** | **OPEN** only if you installed MySQL/WordPress |

### **Scanning Public Websites**
Try scanning `google.com` with ports 1-100. You'll see:
- **Port 80 & 443: OPEN** (web traffic)
- **Everything else: CLOSED** (professional security)

---

## 🎓 Beginner Examples

| Target | Ports | What You'll Learn |
|--------|-------|-------------------|
| `127.0.0.1` | 1-100 | What services YOUR computer runs |
| `192.168.1.1` | 1-100 | Your router's management ports |
| `google.com` | 80-85 | How web servers lock down security |
| `scanme.nmap.org` | 1-100 | **SAFE** public test server |

---

## ⚠️ Important Warnings

**DO NOT scan random websites aggressively** – It's like knocking on every door in a neighborhood. Use only for learning on your own machines or public test servers.

**This tool is for EDUCATION ONLY** – Understand network security, don't misuse it.

---

## 🔧 Troubleshooting

### **"Python not found" error?**
- Install Python from [python.org](https://python.org)
- **IMPORTANT**: Check "Add Python to PATH" during installation

### **Window crashes or freezes?**
- You probably interrupted a scan. Close and re-open.

### **All ports show "Closed" too fast?**
- Your firewall is blocking the scan. Try scanning `127.0.0.1` instead.

### **Scan is very slow?**
- Normal for large ranges (1-65535). Use "Common Ports" button for quick tests.

---

## 📚 Learning Resources Included

The code has **built-in comments** explaining every function. Key topics covered:

- **Socket programming** – How network connections work
- **Threading** – Why GUIs freeze without it
- **Port states** – What open/closed/filtered really means
- **Service names** – What each port is used for

---

## 🛠️ Customization

All settings are at the top of `port_scanner.py`:

```python
DEFAULT_TIMEOUT = 2      # Make this 5 for slower networks
SCAN_DELAY = 0.02        # Increase to 0.1 for less CPU usage
