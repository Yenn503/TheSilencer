# TheSilencer Project 
- AV evasion = Active
- EDR evasion = unknown / untested 
- This solution contains three interrelated projects for malware development research and learning.

## Projects

### Features
- API function hashing using DJB2 algorithm
- Dynamic key path generation for persistence
- Anti-analysis sleep mechanisms
- Windows Run key persistence
- Real-time progress monitoring
- Memory cleanup routines
- Hell's Gate/Hall syscall implementation
- Indirect syscall resolution
- Dynamic API resolution at runtime
- Anti-debugging mechanisms
- Custom exception handling
- Memory section management
- Secure string operations
- Network protocol simulation
- Jitter-based sleep routines
- Random component generation
- Process injection capabilities
- Section remapping techniques
- Dynamic memory allocation
- Secure resource handling
- DLL unhooking via KnownDlls
- Entropy-based timing functions
- Registry operations obfuscation
- Resource encryption/decryption

### 1. Loader
- Main loader implementation with network-themed API obfuscation
- Resource decryption and injection capabilities
- DLL unhooking functionality
- Registry-based persistence mechanism
- Entropy-based timing functions
- Progress-based UI for debugging
- Located in `/Loader` directory

### 2. PayloadEncrypter
- Encrypts payloads for the loader
- AES encryption implementation
- Resource embedding capabilities
- Located in `/PayloadEncrypter` directory

### 3. HashCalculator
- Calculates hashes for API function names
- Generates obfuscated function name constants
- Assists in API hiding implementation
- Located in `/HashCalculator` directory

## Building

1. Open `TheSilencer.sln` in Visual Studio
2. Set build configuration to Release/x64
3. Build solution (all three projects will build)

## Project Dependencies

- Loader: Requires encrypted payload from PayloadEncrypter
- PayloadEncrypter: Standalone
- HashCalculator: Standalone

## Requirements

- Visual Studio 2019 or later
- Windows SDK 10.0
- MASM build tools

## Usage Order

1. Use HashCalculator to generate API hashes
2. Use PayloadEncrypter to prepare encrypted payload
3. Use Loader to execute the encrypted payload with persistence

## Project Structure
TheSilencer/
├── Loader/              # Main loader implementation
├── PayloadEncrypter/    # Payload encryption tool
└── HashCalculator/      # Hash calculation utility

