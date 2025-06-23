![image](https://github.com/user-attachments/assets/62507147-11f5-4956-93d8-7055054afa15)

# GuiGet.ps1 Summary

## 💡 Overview

`GuiGet.ps1` is a comprehensive PowerShell script designed to manage and automate software updates on Windows systems via the **WinGet** package manager. The problem GuiGet solves is, enforcing updates while allowing the end user to deferral options. It supports encrypted or unencrypted settings files, logging, GUI prompts, and custom update workflows tailored to enterprise or personal use cases.

## 🚀 Main Features

- Fetches update settings from a **URL** or **local file**
- Supports **encrypted settings** using AES
- **WinGet integration** for package update automation
- **Logging and log rotation**
- **User interaction via GUI dialogs**
- Optional **fallback update paths**
- **App-specific logic** 
- **Graceful error handling and logging**


## 🔐 Settings and Security

- Settings file can be pulled from:
  - A remote URL (`$settings_url`)
  - A local file path (`$settings_local`)
- Optional encryption with provided 256-bit key (`$key`) and IV (`$iv`)
- Encrypted files are handled using AES decryption logic

## 📦 Dependencies

- **PowerShell 5.1+**
- **WinGet**
- May rely on external JSON settings file for per-app update configuration

## 🧭 Workflow Summary

1. Parse input parameters and load settings
2. Decrypt settings if encryption is enabled
3. Parse JSON configuration for app update instructions
4. Rotate logs and initialize logging system
5. Iterate over configured applications:
   - Check if installed
   - Force close if required
   - Run WinGet update commands
   - Run post-update commands
6. Display results or errors to user
7. Exit gracefully

---

> **Author:** Sarkis Fesliyan  


