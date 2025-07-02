# MaldevAcademy Projects

This solution contains three interrelated projects for malware development research and learning.

## Projects

### 1. Loader
- Main loader implementation with network-themed API obfuscation
- Resource decryption and injection capabilities
- DLL unhooking functionality
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

1. Open `MaldevAcademy.sln` in Visual Studio
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
3. Use Loader to execute the encrypted payload

## Project Structure
MaldevAcademy/
??? Loader/              # Main loader implementation
??? PayloadEncrypter/    # Payload encryption tool
??? HashCalculator/      # Hash calculation utility

