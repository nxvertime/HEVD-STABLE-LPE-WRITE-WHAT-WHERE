# HEVD Stable LPE – Arbitrary Read/Write (Write-What-Where)

🚀 Proof-of-Concept exploit against **HackSys Extreme Vulnerable Driver (HEVD)** leveraging the **Arbitrary Write-What-Where** vulnerability to achieve **Local Privilege Escalation (LPE)** on Windows.

This implementation is made stable across different **Windows 10 builds** by dynamically resolving `EPROCESS` field offsets via **pattern scanning** of `ntoskrnl.exe`.

---

## ✨ Features
- 🔍 **Dynamic offset resolution** for:
  - `UniqueProcessId`
  - `Token`
  - `ActiveProcessLinks`
- 📖 Pattern scanning directly inside `ntoskrnl.exe`
- ⚡ Arbitrary **read/write primitives**
- 🛠️ Clean code, separated into headers/sources
- 🐚 Spawns a SYSTEM shell (`cmd.exe`) once successful
- 💡 Data-only exploit → bypasses most kernel mitigations (SMEP, CFG, etc.)


## ⚙️ Build

- Clone the repo:
   ```bash
   git clone https://github.com/nxvertime/HEVD-STABLE-LPE-WRITE-WHAT-WHERE.git
   cd HEVD-STABLE-LPE-WRITE-WHAT-WHERE
   ```
- Open hevd_arbitrary_rw.sln with Visual Studio
- Build in x64 / Release
- Ensure HEVD.sys is loaded on the target system


## 🚀 Usage
- Load HackSys Extreme Vulnerable Driver:

    ```bash
    sc create HEVD type= kernel binPath= C:\Path\To\HEVD.sys
    sc start HEVD
    ```
- Run the exploit binary as low-privileged user

- Enjoy your SYSTEM shell:
![alt](https://i.imgur.com/JhTtJuW.png)
## 🧪 Tested On
Microsoft Windows 10 (build 19044.1288)

Works reliably across multiple W10 builds thanks to dynamic offset scanning

## ⚠️ Disclaimer
This code is provided for educational and research purposes only.
Do not use it on systems you do not own or have explicit permission to test.
The author is not responsible for any misuse or damage caused.

💻 Author: @nxvertime aka 0xc0ffeebabe
