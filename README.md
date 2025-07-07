# 🔇 TheSilencer Project 

A custom loader that utilises MalDevs Academy implementation of process injection. Which has been further enhanced and modified for stealth and evasion. TheSilencer is designed to bypass modern antivirus and EDR solutions while maintaining a low profile during execution.

### 🎯 AV Bypass Status

| Antivirus Solution | Status |
|-------------------|--------|
| Windows Defender | ✅ ACTIVE |

### 🎯 EDR Bypass Status

| EDR Solution | Status |
|--------------|--------|
| SOPHOS EDR/XDR | ✅ TESTED & WORKING |
| Cronos EDR | NEXT TO BE TESTED |

## 🎯 Core Features

### 🕵️ Evasion & Stealth
- DLL unhooking via KnownDlls
- API hashing/resolution
- Hell's Gate/Hall syscalls
- Anti-debugging mechanisms
- Jitter sleep routines
- Memory cleanup procedures
- 
### 📦 Payload Handling
- AES encryption
- Resource embedding
- Clean injection
- Secure decryption

### 🛡️ Operational Security
- Network simulation
- Debug-only UI
- Memory management
- String sanitization

### ⚡ Auto-Execution
- Boot-time execution
- C2 payload delivery
- Registry persistence
- Error handling

## 🚀 Components

### 1. Loader
- Network-themed API obfuscation
- Resource handling & injection
- DLL unhooking implementation
- Registry persistence system
- Entropy-based timing
- ETW bypass mechanism with jittering
- Chunked memory operations
- Debug progress UI
- `/Loader` directory

### 2. PayloadEncrypter
- Payload encryption system
- AES implementation
- Resource embedding tools
- `/PayloadEncrypter` directory

### 3. HashCalculator
- API hash generation
- Function name obfuscation
- API hiding support
- `/HashCalculator` directory

## ⚙️ Building
1. Open `TheSilencer.sln`
2. Select Release/x64 config
3. Build full solution

## 📋 Requirements
- Visual Studio 2019+
- Windows SDK 10.0
- MASM build tools

## 🔄 Dependencies
- Loader ← PayloadEncrypter
- PayloadEncrypter (Standalone)
- HashCalculator (Standalone)

## 📝 Usage
1. Generate API hashes (HashCalculator)
2. Prepare encrypted payload (PayloadEncrypter)
3. Execute payload (Loader)

## 📂 Structure
TheSilencer/
├── Loader/              # Core loader
├── PayloadEncrypter/    # Encryption tools
└── HashCalculator/      # Hash utilities

