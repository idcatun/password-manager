# SecureVault – Password Manager

A secure, local-first password manager with a GTK3 graphical interface.

## Security

| Layer | Detail |
|---|---|
| Encryption | AES-256-CBC |
| Key derivation | PBKDF2-HMAC-SHA256, 100,000 iterations |
| Salt | 256-bit random, stored separately from vault |
| Storage | `~/.securevault/vault.dat` (encrypted) + `vault.salt` |

Your master password is **never stored**. The salt + iteration count mean brute-forcing
the vault requires 100,000 SHA-256 hashes *per guess* — expensive enough to deter
even GPU-accelerated attacks.

---

## Building the Windows EXE

### One-time setup (Windows only)

1. **Download RubyInstaller** (with DevKit) from https://rubyinstaller.org  
   Choose the **64-bit Ruby+Devkit 3.x** installer.

2. Run the installer. When prompted, keep the box checked to run `ridk install`.

3. In the MSYS2 shell that opens, type `1` and press Enter to install the base toolchain.

4. Open a new **Start Command Prompt with Ruby** and run:

   ```bat
   ridk install
   gem install gtk3
   gem install ocra
   ```

   > `gem install gtk3` downloads GTK3 DLLs via MSYS2 — takes 3–5 minutes.

### Build the EXE

From this project folder:

```bat
build_windows.bat
```

This produces **`SecureVault.exe`** — a self-contained executable that includes the Ruby
interpreter, all gems, and GTK3 runtime DLLs. No installation required on the target machine.

### Build a polished installer (optional)

After producing `SecureVault.exe`:

1. Download **Inno Setup** from https://jrsoftware.org/isinfo.php
2. Open `SecureVault.iss` in the Inno Setup Compiler
3. Press **Compile** (Ctrl+F9)
4. Find `Output\SecureVaultSetup.exe` — a proper Windows installer with Start Menu
   shortcuts, a desktop icon, and an uninstaller.

---

## Running on Linux / macOS

```bash
chmod +x setup.sh
./setup.sh
```

Or manually:

```bash
# Debian/Ubuntu
sudo apt install ruby ruby-gtk3

# macOS
brew install ruby gtk+3

# Run
ruby securevault.rb
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+N` | Add new credential |
| `Ctrl+F` | Focus search bar |
| `Ctrl+L` | Lock vault |
| Double-click entry | Edit credential |

---

## Vault File Location

| OS | Path |
|---|---|
| Windows | `C:\Users\<you>\.securevault\` |
| Linux | `~/.securevault/` |
| macOS | `~/.securevault/` |

`vault.dat` — AES-256-CBC encrypted JSON  
`vault.salt` — 256-bit random salt (keep this alongside `vault.dat` for backups)
