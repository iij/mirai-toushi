# mirai-toushi
Cross-Architecture Mirai Configuration Extractor Utilizing Standalone Ghidra Script

- Supported architectures
  - ARM
  - MC68000
  - MIPS
  - PowerPC
  - SPARC
  - SuperH4
  - x86
  - x86_64

- Supported Ghidra versions
  - 10.2.2 ≤ version ≤ 12.0.4

This work was presented at Botconf2025.
- Slide: https://www.botconf.eu/wp-content/uploads/formidable/2/BOTCONF2025-mirai-toushi-botconf2025.pdf
- Paper: https://cyberjournal.cecyf.fr/index.php/cybin/article/view/56
  - Tested on Ghidra 10.2.2
```
@article{morishita2025mirai,
  title={mirai-toushi: Cross-Architecture Mirai Configuration Extractor Utilizing Standalone Ghidra Script},
  author={Morishita, Shun and Kobayashi, Satoshi and Hombu, Eisei},
  journal={The Journal on Cybercrime and Digital Investigations},
  volume={10},
  number={1},
  pages={1--11},
  year={2025}
}
```

## Ghidra scripts

### 1. xor_scanner.py
- Extract xor data (password list) from Mirai scanner.c

### 2. xor_table.py
- Extract xor data (e.g., C2, Scan Receiver, DoS parameter) from Mirai table.c

### 3. parse_main.py
- Extract additional data (e.g., C2 in resolv_cnc_addr(), DoS function) from Mirai main.c/attack.c

### 4. cnc_scanner.py (Experimental: Newly added in https://github.com/iij/mirai-toushi/pull/1)
- Extract C2 endpoints that are hardcoded as numeric immediates (sockaddr_in setup)

## Usage
*** Malware must be unpacked before running Ghidra script

### 1. Install Ghidra
- https://ghidra-sre.org/

### 2. Run Ghidra script
Two ways of mirai-toushi usage without additional library/tool
- Jython interpreter
- Headless analyzer

#### 2-1. Jython interpreter
- Open target malware with Ghidra GUI
- Start Ghidra Jython interpreter
  - "Window" menu -> "Jython" (or "Python" before Ghidra 11.2)
- Copy-paste target Ghidra script to interpreter

#### 2-2. Headless analyzer
- Check your $GHIDRA_INSTALL_DIR
  - At REMnux case, default directory is `/opt/ghidra`
- Start runner.sh

```bash
$ chmod +x runner.sh
$ GHIDRA_INSTALL_DIR=<GHIDRA_INSTALL_DIR> ./runner.sh <ELF_FILE>
```

- mirai-toushi results will be output to `./output/<SHA256>/` directory by default
  - output JSON Schema: [./jsonschema](./jsonschema)
  - output sample: [./sample](./sample)
