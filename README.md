
![Screenshot 2025-06-23 at 8 21 40 PM](https://github.com/user-attachments/assets/fb22cb11-6dc0-48fc-90c2-a70f9cd43232)

# GuiGet.ps1 Summary

## 💡 Overview

`GuiGet.ps1` is a comprehensive PowerShell script designed to manage and automate software updates on Windows systems via the **WinGet** package manager. The problem GuiGet solves is, enforcing updates while allowing the end user to deferral options. It supports encrypted or unencrypted settings files, logging, GUI prompts, and custom update workflows tailored to enterprise or personal use cases.

## 🚀 Main Features

- Fetches update settings from a **URL** or **local file**
- Supports **encrypted settings** using AES
- **WinGet integration** for package update automation
- Forced updates
- Silent updates
- Deferral updates
- enforce minimum application versions
- **Logging and log rotation**
- **User interaction via GUI dialogs**
- **App-specific update arguments logic** 
- **Graceful error handling and logging**
- Complete control over UI Design
- Notification center notifications

## 🔐 Notifications
Missed deadline notification

![image (91)](https://github.com/user-attachments/assets/5248b91c-9176-41f0-9075-ee452d156b45)

Standard notification
![Notifications](https://github.com/user-attachments/assets/d07d44b0-a642-46c9-b6ac-fee7525480aa)




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


