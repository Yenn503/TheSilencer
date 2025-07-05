# 🔇 TheSilencer Project 

## 🛡️ Status
- AV Evasion: ✅ Active
- EDR Evasion: ⚠️ Untested
- Type: Research & Learning Project

## 🎯 Core Features

### 🕵️ Evasion & Stealth
- DLL unhooking via KnownDlls
- API hashing/resolution
- Hell's Gate/Hall syscalls
- Anti-debugging mechanisms
- Jitter sleep routines
- Memory cleanup procedures

### 🔐 Persistence
- Run key implementation
- Dynamic/random key names
- Windows path blending
- Reboot survival

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
3. Execute payload with persistence (Loader)

## 📂 StructureTheSilencer/
├── Loader/              # Core loader
├── PayloadEncrypter/    # Encryption tools
└── HashCalculator/      # Hash utilities

