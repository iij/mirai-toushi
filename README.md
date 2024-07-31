# mirai-toushi
Cross-Architecture Mirai Configuration Extractor Utilizing Standalone Ghidra Script

**This work will be presented at Computer Security Symposium 2024 (Japanese conference)**

- Tested version
  - Ghidra 10.2.2 / Java 17.0.7

- Supported architectures
  - ARM
  - MC68000
  - MIPS
  - PowerPC
  - SPARC
  - SuperH4
  - x86
  - x86_64

## Ghidra scripts

### 1. xor_scanner.py
- Extract xor data (password list) from Mirai scanner.c

### 2. xor_table.py
- Extract xor data (e.g., C2, Scan Receiver, DoS parameter) from Mirai table.c

## Usage
*** Malware must be unpacked before running Ghidra script

### 1. Install Ghidra
- https://ghidra-sre.org/

### 2. Run Ghidra script
Two ways of mirai-toushi usage without additional library/tool
- Python interpreter
- Headless analyzer

#### 2-1. Python interpreter
- Open target malware with Ghidra GUI
- Start Ghidra python interpreter
  - "Window" menu -> "Python"
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
