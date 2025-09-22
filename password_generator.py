#!/usr/bin/env python3
"""
Secure Password Generator
A cryptographically secure password generator with CLI and GUI interfaces.

Features:
- CSPRNG-based generation using secrets module
- Customizable character sets and length
- Entropy calculation and strength scoring
- Policy templates for different use cases
- Passphrase generation using diceware
- GUI with clipboard integration
- Export functionality with encryption
- No persistent storage of generated passwords

Security considerations:
- Uses secrets module (CSPRNG)
- Memory hygiene with variable clearing
- Encrypted exports only
- Clipboard security warnings
"""

import secrets
import string
import math
import argparse
import sys
import json
import csv
import hashlib
import base64
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
import threading
import time

# Diceware wordlist (subset for demo - in production, use full EFF wordlist)
DICEWARE_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "academy", "accept", "access", "accident", "account", "accurate", "achieve", "acid",
    "acoustic", "acquire", "across", "action", "active", "actual", "adapt", "add",
    "adequate", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
    "afford", "afraid", "again", "agent", "agree", "ahead", "aim", "air", "airport",
    "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow",
    "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
    "approve", "april", "arcade", "arch", "arctic", "area", "arena", "argue",
    "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive",
    "arrow", "art", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful"
]

class StrengthLevel(Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"

@dataclass
class PasswordPolicy:
    name: str
    min_length: int
    max_length: int
    require_lowercase: bool = True
    require_uppercase: bool = True
    require_digits: bool = True
    require_symbols: bool = True
    exclude_ambiguous: bool = False
    min_entropy: float = 80.0

class PasswordGenerator:
    """Secure password generator using CSPRNG."""
    
    # Character sets
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    AMBIGUOUS = "0O1lI"
    
    # Predefined policies
    POLICIES = {
        "default": PasswordPolicy("Default", 12, 128),
        "bank": PasswordPolicy("Banking", 12, 32, exclude_ambiguous=True, min_entropy=90.0),
        "enterprise": PasswordPolicy("Enterprise", 14, 64, min_entropy=100.0),
        "github": PasswordPolicy("GitHub", 8, 100, require_symbols=False),
        "wifi": PasswordPolicy("WiFi", 12, 63, exclude_ambiguous=True),
        "high_security": PasswordPolicy("High Security", 16, 128, min_entropy=120.0)
    }
    
    def __init__(self):
        self.clear_clipboard_timer = None
    
    def build_charset(self, include_lowercase=True, include_uppercase=True, 
                     include_digits=True, include_symbols=True, 
                     exclude_ambiguous=False) -> str:
        """Build character set based on options."""
        charset = ""
        
        if include_lowercase:
            charset += self.LOWERCASE
        if include_uppercase:
            charset += self.UPPERCASE
        if include_digits:
            charset += self.DIGITS
        if include_symbols:
            charset += self.SYMBOLS
            
        if exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.AMBIGUOUS)
            
        if not charset:
            raise ValueError("At least one character type must be included")
            
        return charset
    
    def generate_password(self, length=16, **kwargs) -> str:
        """Generate a cryptographically secure password."""
        if length < 1:
            raise ValueError("Password length must be at least 1")
            
        charset = self.build_charset(**kwargs)
        
        # Ensure we have at least one character from each required type
        password_chars = []
        required_types = []
        
        if kwargs.get('include_lowercase', True):
            chars = self.LOWERCASE
            if kwargs.get('exclude_ambiguous', False):
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_types.append(chars)
            
        if kwargs.get('include_uppercase', True):
            chars = self.UPPERCASE  
            if kwargs.get('exclude_ambiguous', False):
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_types.append(chars)
            
        if kwargs.get('include_digits', True):
            chars = self.DIGITS
            if kwargs.get('exclude_ambiguous', False):
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_types.append(chars)
            
        if kwargs.get('include_symbols', True):
            required_types.append(self.SYMBOLS)
        
        # Add one character from each required type
        for char_type in required_types:
            if char_type and len(password_chars) < length:
                password_chars.append(secrets.choice(char_type))
        
        # Fill remaining positions with random characters from full charset
        while len(password_chars) < length:
            password_chars.append(secrets.choice(charset))
        
        # Shuffle the password to avoid predictable patterns
        for i in range(len(password_chars)):
            j = secrets.randbelow(len(password_chars))
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        
        password = ''.join(password_chars)
        
        # Clear sensitive variables
        charset = None
        password_chars = None
        required_types = None
        
        return password
    
    def generate_passphrase(self, word_count=6, separator="-", 
                          capitalize=False) -> str:
        """Generate a diceware-style passphrase."""
        if word_count < 1:
            raise ValueError("Word count must be at least 1")
            
        words = []
        for _ in range(word_count):
            word = secrets.choice(DICEWARE_WORDS)
            if capitalize:
                word = word.capitalize()
            words.append(word)
        
        passphrase = separator.join(words)
        
        # Clear sensitive variables
        words = None
        
        return passphrase
    
    def calculate_entropy(self, password: str, charset_size: int) -> float:
        """Calculate password entropy in bits."""
        return len(password) * math.log2(charset_size)
    
    def assess_strength(self, password: str, charset_size: int) -> Tuple[float, StrengthLevel]:
        """Assess password strength based on entropy."""
        entropy = self.calculate_entropy(password, charset_size)
        
        if entropy < 30:
            level = StrengthLevel.VERY_WEAK
        elif entropy < 50:
            level = StrengthLevel.WEAK
        elif entropy < 70:
            level = StrengthLevel.MODERATE
        elif entropy < 90:
            level = StrengthLevel.STRONG
        else:
            level = StrengthLevel.VERY_STRONG
            
        return entropy, level
    
    def copy_to_clipboard(self, text: str, clear_after: int = 30):
        """Copy text to clipboard with optional auto-clear."""
        try:
            pyperclip.copy(text)
            print(f"Password copied to clipboard (will clear in {clear_after}s)")
            
            # Clear previous timer
            if self.clear_clipboard_timer:
                self.clear_clipboard_timer.cancel()
            
            # Set new timer to clear clipboard
            self.clear_clipboard_timer = threading.Timer(clear_after, self._clear_clipboard)
            self.clear_clipboard_timer.start()
            
        except Exception as e:
            print(f"Failed to copy to clipboard: {e}")
    
    def _clear_clipboard(self):
        """Clear clipboard contents."""
        try:
            pyperclip.copy("")
            print("Clipboard cleared for security")
        except Exception as e:
            print(f"Failed to clear clipboard: {e}")
    
    def validate_policy(self, password: str, policy: PasswordPolicy) -> List[str]:
        """Validate password against policy requirements."""
        violations = []
        
        if len(password) < policy.min_length:
            violations.append(f"Password too short (min: {policy.min_length})")
        if len(password) > policy.max_length:
            violations.append(f"Password too long (max: {policy.max_length})")
            
        if policy.require_lowercase and not any(c.islower() for c in password):
            violations.append("Missing lowercase letter")
        if policy.require_uppercase and not any(c.isupper() for c in password):
            violations.append("Missing uppercase letter")
        if policy.require_digits and not any(c.isdigit() for c in password):
            violations.append("Missing digit")
        if policy.require_symbols and not any(c in self.SYMBOLS for c in password):
            violations.append("Missing symbol")
            
        if policy.exclude_ambiguous and any(c in self.AMBIGUOUS for c in password):
            violations.append("Contains ambiguous characters")
            
        return violations
    
    def export_passwords(self, passwords: List[Dict], filepath: str, 
                        passphrase: str = None):
        """Export passwords to encrypted file."""
        if not passphrase:
            raise ValueError("Passphrase required for export")
        
        # Simple encryption using AES-like approach (demo)
        # In production, use proper cryptographic libraries like cryptography
        data = json.dumps(passwords, indent=2)
        
        # Hash passphrase for key derivation (simplified)
        key = hashlib.sha256(passphrase.encode()).digest()
        
        # Simple XOR encryption (demo - use proper AES in production)
        encrypted_data = bytearray()
        for i, byte in enumerate(data.encode()):
            encrypted_data.append(byte ^ key[i % len(key)])
        
        # Encode and save
        encoded_data = base64.b64encode(encrypted_data).decode()
        
        with open(filepath, 'w') as f:
            f.write(encoded_data)
        
        # Clear sensitive data
        data = None
        key = None
        encrypted_data = None
        passphrase = None


class PasswordGeneratorGUI:
    """GUI interface for password generator."""
    
    def __init__(self):
        self.generator = PasswordGenerator()
        self.root = tk.Tk()
        self.root.title("Secure Password Generator")
        self.root.geometry("600x700")
        
        self.setup_ui()
        self.generated_passwords = []
    
    def setup_ui(self):
        """Setup the GUI interface."""
        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Password Generator Tab
        self.setup_password_tab(notebook)
        
        # Passphrase Generator Tab
        self.setup_passphrase_tab(notebook)
        
        # Export Tab
        self.setup_export_tab(notebook)
    
    def setup_password_tab(self, parent):
        """Setup password generation tab."""
        frame = ttk.Frame(parent)
        parent.add(frame, text="Password Generator")
        
        # Policy selection
        policy_frame = ttk.LabelFrame(frame, text="Policy Template")
        policy_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.policy_var = tk.StringVar(value="default")
        policy_combo = ttk.Combobox(policy_frame, textvariable=self.policy_var,
                                   values=list(self.generator.POLICIES.keys()),
                                   state="readonly")
        policy_combo.pack(padx=5, pady=5)
        policy_combo.bind('<<ComboboxSelected>>', self.on_policy_change)
        
        # Length selection
        length_frame = ttk.LabelFrame(frame, text="Password Length")
        length_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(length_frame, from_=8, to=128, 
                               variable=self.length_var, orient=tk.HORIZONTAL)
        length_scale.pack(fill=tk.X, padx=5, pady=2)
        
        length_label = ttk.Label(length_frame, textvariable=self.length_var)
        length_label.pack(pady=2)
        
        # Character options
        options_frame = ttk.LabelFrame(frame, text="Character Options")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_ambiguous_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(options_frame, text="Lowercase (a-z)", 
                       variable=self.lowercase_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", 
                       variable=self.uppercase_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", 
                       variable=self.digits_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Symbols (!@#$...)", 
                       variable=self.symbols_var).pack(anchor=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Exclude ambiguous (0O1lI)", 
                       variable=self.exclude_ambiguous_var).pack(anchor=tk.W, padx=5)
        
        # Generate button
        ttk.Button(frame, text="Generate Password", 
                  command=self.generate_password_gui).pack(pady=10)
        
        # Result display
        result_frame = ttk.LabelFrame(frame, text="Generated Password")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Password display with show/hide
        password_frame = ttk.Frame(result_frame)
        password_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var,
                                       show="*", font=("Consolas", 12))
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(password_frame, text="Show", 
                                   variable=self.show_var,
                                   command=self.toggle_password_visibility)
        show_check.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Copy button
        ttk.Button(result_frame, text="Copy to Clipboard", 
                  command=self.copy_password).pack(pady=5)
        
        # Strength info
        self.strength_var = tk.StringVar()
        self.entropy_var = tk.StringVar()
        
        ttk.Label(result_frame, textvariable=self.strength_var,
                 font=("Arial", 10, "bold")).pack(pady=2)
        ttk.Label(result_frame, textvariable=self.entropy_var).pack(pady=2)
    
    def setup_passphrase_tab(self, parent):
        """Setup passphrase generation tab."""
        frame = ttk.Frame(parent)
        parent.add(frame, text="Passphrase Generator")
        
        # Word count
        count_frame = ttk.LabelFrame(frame, text="Number of Words")
        count_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.word_count_var = tk.IntVar(value=6)
        count_scale = ttk.Scale(count_frame, from_=3, to=12, 
                              variable=self.word_count_var, orient=tk.HORIZONTAL)
        count_scale.pack(fill=tk.X, padx=5, pady=2)
        
        count_label = ttk.Label(count_frame, textvariable=self.word_count_var)
        count_label.pack(pady=2)
        
        # Separator
        sep_frame = ttk.LabelFrame(frame, text="Word Separator")
        sep_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.separator_var = tk.StringVar(value="-")
        ttk.Entry(sep_frame, textvariable=self.separator_var, width=10).pack(padx=5, pady=5)
        
        # Options
        self.capitalize_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Capitalize first letter of each word", 
                       variable=self.capitalize_var).pack(anchor=tk.W, padx=5, pady=5)
        
        # Generate button
        ttk.Button(frame, text="Generate Passphrase", 
                  command=self.generate_passphrase_gui).pack(pady=10)
        
        # Result display
        result_frame = ttk.LabelFrame(frame, text="Generated Passphrase")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.passphrase_var = tk.StringVar()
        passphrase_entry = ttk.Entry(result_frame, textvariable=self.passphrase_var,
                                   font=("Consolas", 12))
        passphrase_entry.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(result_frame, text="Copy to Clipboard", 
                  command=self.copy_passphrase).pack(pady=5)
        
        self.passphrase_strength_var = tk.StringVar()
        ttk.Label(result_frame, textvariable=self.passphrase_strength_var,
                 font=("Arial", 10, "bold")).pack(pady=2)
    
    def setup_export_tab(self, parent):
        """Setup export functionality tab."""
        frame = ttk.Frame(parent)
        parent.add(frame, text="Export")
        
        info_label = ttk.Label(frame, 
                              text="Export generated passwords to encrypted file\n"
                                   "Passwords are stored in memory only during session",
                              justify=tk.CENTER)
        info_label.pack(pady=20)
        
        # Password list
        list_frame = ttk.LabelFrame(frame, text="Generated Passwords (Session)")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.password_listbox = tk.Listbox(list_frame, height=10)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, 
                                 command=self.password_listbox.yview)
        self.password_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.password_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Export button
        ttk.Button(frame, text="Export to Encrypted File", 
                  command=self.export_passwords_gui).pack(pady=10)
    
    def on_policy_change(self, event=None):
        """Handle policy template change."""
        policy_name = self.policy_var.get()
        policy = self.generator.POLICIES[policy_name]
        
        # Update UI with policy settings
        self.length_var.set(policy.min_length)
        self.lowercase_var.set(policy.require_lowercase)
        self.uppercase_var.set(policy.require_uppercase)
        self.digits_var.set(policy.require_digits)
        self.symbols_var.set(policy.require_symbols)
        self.exclude_ambiguous_var.set(policy.exclude_ambiguous)
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def generate_password_gui(self):
        """Generate password from GUI settings."""
        try:
            password = self.generator.generate_password(
                length=self.length_var.get(),
                include_lowercase=self.lowercase_var.get(),
                include_uppercase=self.uppercase_var.get(),
                include_digits=self.digits_var.get(),
                include_symbols=self.symbols_var.get(),
                exclude_ambiguous=self.exclude_ambiguous_var.get()
            )
            
            self.password_var.set(password)
            
            # Calculate charset size for entropy
            charset = self.generator.build_charset(
                include_lowercase=self.lowercase_var.get(),
                include_uppercase=self.uppercase_var.get(),
                include_digits=self.digits_var.get(),
                include_symbols=self.symbols_var.get(),
                exclude_ambiguous=self.exclude_ambiguous_var.get()
            )
            
            entropy, strength = self.generator.assess_strength(password, len(charset))
            
            self.strength_var.set(f"Strength: {strength.value}")
            self.entropy_var.set(f"Entropy: {entropy:.1f} bits")
            
            # Add to generated passwords list
            self.generated_passwords.append({
                'type': 'password',
                'value': password,
                'length': len(password),
                'entropy': entropy,
                'strength': strength.value,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            
            # Update export list
            self.update_export_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {e}")
    
    def generate_passphrase_gui(self):
        """Generate passphrase from GUI settings."""
        try:
            passphrase = self.generator.generate_passphrase(
                word_count=self.word_count_var.get(),
                separator=self.separator_var.get(),
                capitalize=self.capitalize_var.get()
            )
            
            self.passphrase_var.set(passphrase)
            
            # Estimate entropy for passphrase (simplified)
            word_entropy = math.log2(len(DICEWARE_WORDS))
            total_entropy = self.word_count_var.get() * word_entropy
            
            if total_entropy < 50:
                strength = StrengthLevel.WEAK
            elif total_entropy < 70:
                strength = StrengthLevel.MODERATE
            elif total_entropy < 90:
                strength = StrengthLevel.STRONG
            else:
                strength = StrengthLevel.VERY_STRONG
            
            self.passphrase_strength_var.set(
                f"Strength: {strength.value} (~{total_entropy:.1f} bits)"
            )
            
            # Add to generated passwords list
            self.generated_passwords.append({
                'type': 'passphrase',
                'value': passphrase,
                'word_count': self.word_count_var.get(),
                'entropy': total_entropy,
                'strength': strength.value,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            
            self.update_export_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate passphrase: {e}")
    
    def copy_password(self):
        """Copy generated password to clipboard."""
        password = self.password_var.get()
        if password:
            self.generator.copy_to_clipboard(password)
        else:
            messagebox.showwarning("Warning", "No password to copy")
    
    def copy_passphrase(self):
        """Copy generated passphrase to clipboard."""
        passphrase = self.passphrase_var.get()
        if passphrase:
            self.generator.copy_to_clipboard(passphrase)
        else:
            messagebox.showwarning("Warning", "No passphrase to copy")
    
    def update_export_list(self):
        """Update the export list with generated passwords."""
        self.password_listbox.delete(0, tk.END)
        for i, pwd_data in enumerate(self.generated_passwords):
            display_text = f"{i+1}. {pwd_data['type'].title()} - {pwd_data['strength']} - {pwd_data['timestamp']}"
            self.password_listbox.insert(tk.END, display_text)
    
    def export_passwords_gui(self):
        """Export passwords through GUI."""
        if not self.generated_passwords:
            messagebox.showwarning("Warning", "No passwords to export")
            return
        
        # Get export passphrase
        passphrase = tk.simpledialog.askstring("Export Passphrase", 
                                              "Enter passphrase to encrypt export file:",
                                              show='*')
        if not passphrase:
            return
        
        # Get save location
        filepath = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                self.generator.export_passwords(self.generated_passwords, filepath, passphrase)
                messagebox.showinfo("Success", f"Passwords exported to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")
    
    def run(self):
        """Start the GUI."""
        self.root.mainloop()


def cli_interface():
    """Command-line interface for password generator."""
    parser = argparse.ArgumentParser(description="Secure Password Generator")
    parser.add_argument('-l', '--length', type=int, default=16,
                       help='Password length (default: 16)')
    parser.add_argument('--no-lower', action='store_true',
                       help='Exclude lowercase letters')
    parser.add_argument('--no-upper', action='store_true', 
                       help='Exclude uppercase letters')
    parser.add_argument('--no-digits', action='store_true',
                       help='Exclude digits')
    parser.add_argument('--no-symbols', action='store_true',
                       help='Exclude symbols')
    parser.add_argument('--exclude-ambiguous', action='store_true',
                       help='Exclude ambiguous characters (0O1lI)')
    parser.add_argument('--policy', choices=list(PasswordGenerator.POLICIES.keys()),
                       help='Use predefined policy template')
    parser.add_argument('--passphrase', action='store_true',
                       help='Generate passphrase instead of password')
    parser.add_argument('--words', type=int, default=6,
                       help='Number of words in passphrase (default: 6)')
    parser.add_argument('--separator', default='-',
                       help='Word separator for passphrase (default: -)')
    parser.add_argument('--capitalize', action='store_true',
                       help='Capitalize passphrase words')
    parser.add_argument('--copy', action='store_true',
                       help='Copy to clipboard')
    parser.add_argument('--count', type=int, default=1,
                       help='Number of passwords to generate (default: 1)')
    
    args = parser.parse_args()
    
    generator = PasswordGenerator()
    
    try:
        for i in range(args.count):
            if args.passphrase:
                password = generator.generate_passphrase(
                    word_count=args.words,
                    separator=args.separator,
                    capitalize=args.capitalize
                )
                # Estimate entropy for passphrase
                word_entropy = math.log2(len(DICEWARE_WORDS))
                entropy = args.words * word_entropy
                charset_size = len(DICEWARE_WORDS) ** args.words
                
            else:
                # Apply policy if specified
                if args.policy:
                    policy = generator.POLICIES[args.policy]
                    kwargs = {
                        'include_lowercase': not args.no_lower and policy.require_lowercase,
                        'include_uppercase': not args.no_upper and policy.require_uppercase,
                        'include_digits': not args.no_digits and policy.require_digits,
                        'include_symbols': not args.no_symbols and policy.require_symbols,
                        'exclude_ambiguous': args.exclude_ambiguous or policy.exclude_ambiguous
                    }
                    length =