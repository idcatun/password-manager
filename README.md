# SecureVault – Password Manager

A secure, local-first password manager with a GTK3 graphical interface, built in Ruby.

---

## Features

- **AES-256-CBC encryption** with PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- **KEK architecture** — vault key is random and permanent; master password only wraps it, so password resets never touch your data
- **Username + master password** login with Remember Me
- **Security questions** for password recovery — answer any one of three chosen questions
- **Escalating lockout** after failed login attempts
- **Auto-lock** on inactivity
- **Clipboard auto-clear** after 30 seconds
- **Password strength indicator** with per-requirement feedback
- **Password generator** (cryptographically secure)
- **Light and dark mode** with preference saved across sessions
- **Show/hide password** toggle on all password fields

---

## Security Model

### Encryption

| Layer | Detail |
|---|---|
| Vault encryption | AES-256-CBC |
| Key derivation | PBKDF2-HMAC-SHA256, 100,000 iterations |
| Vault key | 256-bit random, generated once at vault creation |
| Master blob | Vault key wrapped under master-password-derived key |
| Recovery blobs | Vault key wrapped independently under each security question answer |

Your master password is **never stored**. The vault key is a random value that never changes — changing your master password or resetting via security questions only re-wraps the vault key, leaving your encrypted data untouched.

### Login Lockout

After 5 consecutive failed login attempts the vault locks for an escalating duration:

| Lockout | Duration |
|---|---|
| 1st | 1 minute |
| 2nd | 5 minutes |
| 3rd | 15 minutes |
| 4th | 1 hour |
| 5th | 1 day |
| 6th+ | 1 week |

Lockout state persists across app restarts and resets only on successful login or vault recreation.

### Other Security Features

- **Auto-lock** — vault locks after 5 minutes of keyboard/mouse inactivity
- **Clipboard wipe** — anything copied via the app is cleared from the clipboard after 30 seconds
- **Constant-time comparison** — security question answers verified with `OpenSSL.fixed_length_secure_compare` to prevent timing attacks

---

## Authentication Flow

### First Run

1. Enter a username and master password (min 8 characters)
2. Choose 3 security questions from a pool of 12 and provide answers
3. Vault is created — you're logged in

### Signing In

- Enter username and master password
- Check **Remember Me** to pre-fill your username next time
- Click **Forgot password?** to reset via a security question

### Password Reset

1. Click **Forgot password?** on the login screen
2. Select any one of your three security questions from the dropdown
3. Enter the answer — if correct, proceed to set a new master password
4. Log in with the new password

---

## Vault Files

All data is stored in `~/.securevault/`:

| File | Contents |
|---|---|
| `vault.dat` | AES-256-CBC encrypted credential store |
| `vault.meta` | Username, master blob, recovery blobs, security question hashes |
| `remember` | Saved username (only if Remember Me is checked) |
| `theme` | Light/dark mode preference |
| `lockout` | Lockout count and expiry (persists across restarts) |

**To fully reset the app:**
```bash
rm -rf ~/.securevault/
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

## Running on Linux / macOS (WSL included)

```bash
# Debian/Ubuntu/WSL
sudo apt install ruby ruby-dev ruby-gtk3 libgtk-3-dev

ruby securevault.rb
```

Or use the included setup script:

```bash
chmod +x setup.sh
./setup.sh
```

---

## Building the Windows EXE

### One-time setup

1. Download **RubyInstaller+Devkit** (64-bit, Ruby 3.x) from https://rubyinstaller.org
2. Run the installer — when prompted, let it run `ridk install`
3. In the MSYS2 prompt, press Enter to accept `[1,3]` (installs full toolchain)
4. Open **Command Prompt** (not PowerShell) and run:

```bat
gem install gtk3 ocra
```

### Build

From the project folder in Command Prompt:

```bat
build_windows.bat
```

Produces `SecureVault.exe` — self-contained, no Ruby required on the target machine.

### Optional: polished installer

1. Download **Inno Setup** from https://jrsoftware.org/isinfo.php
2. Open `SecureVault.iss` and press **Compile** (Ctrl+F9)
3. Find `Output\SecureVaultSetup.exe` — a Windows installer with Start Menu and desktop shortcuts
