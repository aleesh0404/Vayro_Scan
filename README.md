# Vayro_Scan
A very simple and fast port scanner 


VayroScan is a fast, multithreaded TCP port scanner with a modern dark‑theme GUI built on `customtkinter`. It scans all ports **1–65535** on a target host and displays open ports with their common service names. The interface includes real‑time progress, live stats, and a fancy animated glow button.

---

## Features

- **Full port range** – scans ports 1 to 65535 (no configuration needed).  
- **Adjustable thread count** – choose from 100, 200, 300, 500, or 800 concurrent threads.  
- **Real‑time output** – shows each open port with its guessed service.  
- **Live statistics** – open ports, closed ports, total ports (65,535).  
- **Progress bar** – visual feedback during the scan.  
- **Stop / Start** – abort a running scan at any time.  
- **Clear** – wipes the output terminal.  
- **Copy** – copies all scan results to clipboard.  


---

## Requirements

- Python 3.8 or higher  
- `customtkinter`  
- No external network libraries – uses only standard `socket`, `threading`, `queue`, `concurrent.futures`.

---

## Installation

1. **Clone or download** the repository.  
2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows


## Install dependencies:
pip install customtkinter



## Usage

Enter a target – IP address or hostname (e.g., scanme.nmap.org or 192.168.1.1).

Select the number of threads (300 is a good default).

Click START SCAN.

Watch open ports appear in the output area.

Click STOP SCAN to abort early, or let it finish.

Use Clear to erase output, Copy to save results.


## Limitations

Only TCP scanning – no UDP or SYN stealth mode.

Service detection is based on a hard‑coded dictionary (only common ports).

Scanning 65k ports on a slow network may time out many ports – reduce threads or increase timeout manually (change TIMEOUT in the source).

No IPv6 support (IPv4 only).

## License

Feel free to use, modify, and distribute – no restrictions.
