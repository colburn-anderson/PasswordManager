# USB Password Manager

A fully offline, USB-based password manager that encrypts all of your data in a single AES-GCM blob with random padding. Just plug in your flash drive, double-click the standalone executable, and manage your passwords securely—no network or external dependencies required.


## Features

- **One-file bundle**  
  PyInstaller “onefile” executables for Windows and macOS. Just copy the binary (or `.exe`) and `welcome.gif` onto your USB stick.

- **Full-payload encryption**  
  Labels, usernames, passwords, and notes are serialized to JSON, padded to a fixed block size, then AES-GCM encrypted under a PBKDF2-derived key.

- **Random padding**  
  Each encrypted file is padded to obscure its true length and entry count, defeating size-based guessing.

- **Terminal-style input**  
  As you type any password—master or entry—nothing is echoed, (You will not see anything as you type, not even `*`).

- **Clipboard safety**  
  “View” or “Copy” on an entry places the password onto your clipboard.

- **Cross-platform GUI**  
  Built with Tkinter for a lightweight, dependency-free interface on Windows, macOS, or Linux.

  ## Technologies Used

- **Python 3.10+** — core language for application logic  
- **Tkinter** — built-in Python GUI toolkit for cross-platform interface  
- **PyInstaller** — creates standalone one-file executables for Windows/macOS  
- **cryptography** — AES-GCM encryption and PBKDF2-HMAC-SHA256 key derivation  
- **bcrypt** — secure hashing of the master password  
- **pyperclip** — cross-platform clipboard access for copying passwords  
- **JSON** — serialization format for storing entries before encryption  
- **AES-GCM** — authenticated encryption to protect confidentiality and integrity  
- **PBKDF2-HMAC-SHA256** — key stretching for master-password -> AES key  
- **Random padding** — obscures ciphertext length to prevent metadata leakage  

