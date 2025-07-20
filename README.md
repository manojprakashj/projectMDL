# Linux Misconfiguration Detection and Reporting Tool

## Overview

The **Linux Misconfiguration Detection and Reporting Tool** is a Python-based application designed to enhance the security posture of Linux systems. It identifies common misconfigurations in SSH, FTP, and web server configurations, checks for outdated packages, and scans file permissions for potential vulnerabilities. This tool is intended for system administrators, security engineers, and DevOps professionals to efficiently secure Linux environments.

By analyzing configurations and generating detailed, actionable reports in HTML and PDF formats, the tool simplifies the process of identifying and mitigating risks in server setups.

---

## Features

1. **Configuration Analysis**
   - Detects misconfigurations in:
     - **SSH:** Checks for `PermitRootLogin`, `PasswordAuthentication`, and insecure protocols.
     - **FTP:** Identifies anonymous login issues in FTP servers like VSFTPD and ProFTPD.
     - **Web Servers:** Scans Apache and Nginx configurations for unsafe settings like directory listing.
   - Generates recommendations for remediation.
     

2. **Outdated Package Detection**
   - Automatically identifies outdated packages using popular Linux package managers like `apt`, `yum`, `dnf`, and `pacman`.

3. **File Permissions Audit**
   - Finds world-writable files and directories.
   - Detects SUID/SGID files with insecure permissions.

4. **Customizable Reporting**
   - Creates detailed reports in **HTML** and **PDF** formats, complete with graphical visualizations.
   - Categorizes findings by severity levels (High, Medium, Low).

5. **Extensible Configuration**
   - Customizable paths and settings via a `config.ini` file.

6. **Robust Logging**
   - Logs all operations, findings, and errors for troubleshooting and auditing.

---

## Installation

### Prerequisites
- Python 3.6 or higher
- Pip (Python package manager)
- Permissions to read configuration files and execute administrative commands.

## Usage

Run the tool using Python:

```bash
python main.py

