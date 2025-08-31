#  Neon Port Scanner

A lightweight and accurate **Python-based port scanner** built for quick network reconnaissance.  
This tool lets you scan target hosts for open ports with a simple CLI interface.  

---

## ✨ Features
- 🔍 Fast scanning of multiple ports  
- 🎯 Specify single IPs or hostnames  
- 📦 Minimal dependencies (`socket`, `argparse`, `colorama`)  
- ⚡ Easy to extend and customize  

---

## 🛠️ Installation

Clone the repo:
```bash
git clone https://github.com/ALOITH-exe/Neon-Port-Scanner.git
cd Neon-Port-Scanner
````

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the scanner:

```bash
python port_scanner.py -H <target_host> -p <port_range>
```

Example:

```bash
python port_scanner.py -H scanme.nmap.org -p 20-100
```

---

## 📦 Build Executable (Optional)

You can create a standalone `.exe` file using **PyInstaller**:

```bash
pip install pyinstaller
pyinstaller --onefile port_scanner.py
```

The executable will be available inside the `dist/` folder.

---

## 📜 License

MIT License – free to use, modify, and share.

---
