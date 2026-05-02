# NetGuard Security Hub 🛡️

NetGuard is an asynchronous network scanner that scans devices on your local network, performs vulnerability analysis, and calculates your security score.

## 🚀 Getting Started

Follow the steps below to run the project:

### 1. Prerequisites
- **Python 3.8+**
- **Npcap (for Windows):** To enable Scapy's ARP scanning, you must install Npcap from [npcap.com](https://npcap.com/) with the "Install Npcap in WinPcap API-compatible Mode" option selected.
- **Administrator Rights:** It is recommended to run the terminal as **Administrator** for network card access.

### 2. Install Dependencies
Open the terminal in the project directory and run:
```bash
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
python main.py
```

### 4. Access the Interface
Open your browser and go to:
[http://localhost:8001](http://localhost:8001)

---

## 🛠️ Features
- **Asynchronous Scanning:** Fast network discovery without background freezing.
- **Vulnerability Analysis:** Detecting vulnerabilities using NVD (National Vulnerability Database) integration.
- **Filtering & History:** Review past scans with advanced search and pagination support.
- **Reporting:** Export scan results in CSV or JSON format.
- **Scheduled Scans:** Automatic network auditing at your specified intervals.

## 🧪 Tests
To check the stability of the system:
```bash
python -m pytest tests/test_api.py -v
```
