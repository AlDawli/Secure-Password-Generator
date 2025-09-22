# Secure-Password-Generator
A cryptographically secure password generator with both CLI and GUI interfaces.

# Core Features (MVP)
CLI program that generates passwords of user-specified length
Customizable character sets (lowercase, uppercase, digits, symbols)
Option to avoid ambiguous characters (O, 0, I, l)
CSPRNG-based generation using Python's secrets module
No persistent storage of generated passwords
Entropy calculation and strength assessment
Clipboard integration with auto-clear

# Advanced Features
GUI with Tkinter (show/hide password, copy-to-clipboard)
Password policy templates (bank, enterprise, GitHub, etc.)
Passphrase generator using diceware wordlist
Strength meter with entropy calculation
Export functionality with encryption
Memory hygiene and security best practices

# Requirements
Python 3.7+
pyperclip>=1.8.0  # For clipboard functionality
Install Dependencies
bashpip install pyperclip
Optional: Create Virtual Environment
bashpython -m venv password_env
source password_env/bin/activate  # On Windows: password_env\Scripts\activate
pip install pyperclip
Installation
Just install the clipboard dependency:
bashpip install pyperclip
python password_generator.py  # Launches GUI

# Installation
Just install the clipboard dependency:
bashpip install pyperclip
python password_generator.py  # Launches GUI

# Usage
GUI Mode (Default)
Simply run without arguments to launch the graphical interface:
bashpython password_generator.py

# CLI Mode
Use command line arguments for CLI mode:
Basic Password Generation
bash# Generate 16-character password (default)
python password_generator.py --length 16

# Generate 20-character password
python password_generator.py -l 20

# Generate password without symbols
python password_generator.py --no-symbols

# Generate password excluding ambiguous characters
python password_generator.py --exclude-ambiguous
Using Policy Templates
bash# Use banking policy (12+ chars, no ambiguous)
python password_generator.py --policy bank

# Use enterprise policy (14+ chars, high security)
python password_generator.py --policy enterprise

# Use GitHub policy (8+ chars, no symbols required)
python password_generator.py --policy github
Passphrase Generation
bash# Generate 6-word passphrase (default)
python password_generator.py --passphrase

# Generate 8-word passphrase with custom separator
python password_generator.py --passphrase --words 8 --separator "_"

# Generate capitalized passphrase
python password_generator.py --passphrase --capitalize
Clipboard Integration
bash# Copy to clipboard (clears after 30 seconds)
python password_generator.py --copy

# Generate multiple passwords
python password_generator.py --count 5
CLI Examples
bash# High-security password
python password_generator.py --length 24 --policy high_security --copy

# WiFi password (no ambiguous characters)
python password_generator.py --length 20 --exclude-ambiguous

# Memorable passphrase
python password_generator.py --passphrase --words 5 --separator "-" --capitalize

# Enterprise-compliant batch
python password_generator.py --policy enterprise --count 3
Security Features
Cryptographic Security

Uses Python's secrets module (CSPRNG)
No use of random module for password generation
Proper entropy calculation based on character set size

# Memory Hygiene
Sensitive variables cleared after use
No persistent storage of generated passwords
Clipboard auto-clear after 30 seconds

# Policy Compliance
Predefined templates for different use cases
Validation against policy requirements
Entropy requirements enforcement

# Export Security
Passwords encrypted before export
Passphrase-protected export files
No plaintext storage

# Policy Templates
PolicyMin LengthRequirementsUse CaseDefault12All character typesGeneral useBank12All types, no ambiguousBanking/financialEnterprise14All types, 100+ bits entropyCorporateGitHub8Letters/digits (symbols optional)Code repositoriesWiFi12All types, no ambiguousNetwork passwordsHigh Security16All types, 120+ bits entropySensitive accounts
Strength Assessment
Entropy (bits)Strength LevelTime to Crack*< 30Very WeakMinutes30-50WeakHours to days50-70ModerateMonths to years70-90StrongDecades90+Very StrongCenturies+
*Estimated time assuming modern hardware and techniques

# GUI Features
Password Generator Tab
Real-time length adjustment
Character set toggles
Policy template selection
Show/hide password toggle
One-click clipboard copy
Strength and entropy display

# Passphrase Generator Tab
Adjustable word count (3-12)
Custom separators
Capitalization options
Entropy estimation

# Export Tab
Session password history
Encrypted export functionality
No persistent storage
Security Considerations

# Threat Model
Local attackers: Memory clearing, no disk storage
Clipboard leakage: Auto-clear after 30 seconds
Side-channel attacks: CSPRNG usage, proper entropy
Supply chain: Minimal dependencies, standard library focus

# Best Practices
Clear clipboard after use
Don't save passwords in plaintext files
Use appropriate length for threat model
Consider passphrase for memorizable passwords
Use policy templates for compliance

# Limitations
Simplified encryption for exports (demo purposes)
Basic entropy calculation (doesn't account for patterns)
Limited wordlist for passphrases (demo subset)

# Development Notes
For Production Use
Replace demo encryption with proper AES-GCM
Use full EFF diceware wordlist
Implement proper key derivation (PBKDF2/scrypt)
Add breach database integration
Enhanced entropy analysis
Comprehensive policy framework

# Dependencies
Core: Python 3.7+ standard library
GUI: tkinter (usually included)
Clipboard: pyperclip package
Optional: cryptography package for production encryption

# License
This is a demonstration implementation focusing on security best practices and educational value. For production use, consider additional hardening and proper cryptographic libraries.
Contributing

# Key areas for improvement:
Advanced entropy analysis
Breach database integration
Additional export formats
Enhanced policy framework
Browser extension
Mobile app version
