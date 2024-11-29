#!/usr/bin/env python3

import os
import re
import subprocess
import sys
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from weasyprint import HTML, CSS
from jinja2 import Environment, FileSystemLoader
import logging
import argparse
import configparser

# Setup logging
logging.basicConfig(filename='misconfig_detector.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def load_config(config_file='config.ini'):
    """Load configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def check_ssh_config(config):
    """Check SSH configuration for common misconfigurations."""
    findings = []
    ssh_config_path = config.get('SSH', 'ssh_config_path', fallback='/etc/ssh/sshd_config')
    try:
        if os.path.isfile(ssh_config_path):
            with open(ssh_config_path, 'r') as file:
                config_lines = file.readlines()
                for line in config_lines:
                    if re.match(r'^\s*PermitRootLogin\s+yes', line):
                        findings.append('PermitRootLogin is enabled')
                    if re.match(r'^\s*PasswordAuthentication\s+yes', line):
                        findings.append('PasswordAuthentication is enabled')
                    if re.match(r'^\s*Protocol\s+1', line):
                        findings.append('Using SSH Protocol 1, which is insecure')
        else:
            findings.append('SSH configuration file not found')
    except Exception as e:
        logging.error(f'Error checking SSH configuration: {e}')
        findings.append(f'Error checking SSH configuration: {e}')
    return findings


def check_ftp_config(config):
    """Check FTP configuration for anonymous login and other issues."""
    findings = []
    ftp_config_paths = config.get('FTP', 'ftp_config_paths',
                                  fallback='/etc/vsftpd.conf,/etc/proftpd/proftpd.conf').split(',')
    try:
        for path in ftp_config_paths:
            if os.path.isfile(path):
                with open(path, 'r') as file:
                    config_content = file.read()
                    if 'anonymous_enable=YES' in config_content or 'AllowAnonymous on' in config_content:
                        findings.append(f'Anonymous FTP login is enabled in {path}')
    except Exception as e:
        logging.error(f'Error checking FTP configuration: {e}')
        findings.append(f'Error checking FTP configuration: {e}')
    return findings


def check_web_server_config(config):
    """Check web server configurations for directory listing and other issues."""
    findings = []
    # Apache
    apache_config_path = config.get('WebServer', 'apache_config_path', fallback='/etc/apache2/apache2.conf')
    try:
        if os.path.isfile(apache_config_path):
            with open(apache_config_path, 'r') as file:
                config_content = file.read()
                if 'Options Indexes' in config_content:
                    findings.append('Directory listing is enabled in Apache')
    except Exception as e:
        logging.error(f'Error checking Apache configuration: {e}')
        findings.append(f'Error checking Apache configuration: {e}')
    # Nginx
    nginx_config_path = config.get('WebServer', 'nginx_config_path', fallback='/etc/nginx/nginx.conf')
    try:
        if os.path.isfile(nginx_config_path):
            with open(nginx_config_path, 'r') as file:
                config_content = file.read()
                if 'autoindex on' in config_content:
                    findings.append('Directory listing is enabled in Nginx')
    except Exception as e:
        logging.error(f'Error checking Nginx configuration: {e}')
        findings.append(f'Error checking Nginx configuration: {e}')
    return findings


def detect_package_manager():
    """Detect the package manager based on the Linux distribution."""
    try:
        result = subprocess.check_output(['which', 'apt'], stderr=subprocess.DEVNULL)
        if result:
            return 'apt'
    except subprocess.CalledProcessError:
        pass
    try:
        result = subprocess.check_output(['which', 'yum'], stderr=subprocess.DEVNULL)
        if result:
            return 'yum'
    except subprocess.CalledProcessError:
        pass
    try:
        result = subprocess.check_output(['which', 'dnf'], stderr=subprocess.DEVNULL)
        if result:
            return 'dnf'
    except subprocess.CalledProcessError:
        pass
    try:
        result = subprocess.check_output(['which', 'pacman'], stderr=subprocess.DEVNULL)
        if result:
            return 'pacman'
    except subprocess.CalledProcessError:
        pass
    logging.error('Package manager not detected')
    return None


def check_outdated_packages():
    """Check for outdated packages using the detected package manager."""
    findings = []
    pkg_manager = detect_package_manager()
    if not pkg_manager:
        findings.append('No supported package manager detected')
        return findings
    try:
        if pkg_manager == 'apt':
            subprocess.run(['apt-get', 'update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result = subprocess.check_output(['apt', 'list', '--upgradable'], stderr=subprocess.DEVNULL)
            packages = result.decode().split('\n')[1:]
            for pkg in packages:
                if pkg:
                    findings.append(pkg)
        elif pkg_manager == 'yum' or pkg_manager == 'dnf':
            result = subprocess.check_output([pkg_manager, 'check-update'], stderr=subprocess.DEVNULL)
            packages = result.decode().split('\n')
            for pkg in packages:
                if pkg and not pkg.startswith('Loaded plugins') and not pkg.startswith('Last metadata expiration check'):
                    findings.append(pkg)
        elif pkg_manager == 'pacman':
            result = subprocess.check_output(['pacman', '-Qu'], stderr=subprocess.DEVNULL)
            packages = result.decode().split('\n')
            for pkg in packages:
                if pkg:
                    findings.append(pkg)
    except Exception as e:
        logging.error(f'Error checking outdated packages: {e}')
        findings.append(f'Error checking outdated packages: {e}')
    return findings


def check_unwanted_file_permissions():
    """Check for files and directories with insecure permissions."""
    findings = []
    try:
        # World-writable files
        result = subprocess.getoutput("find / -xdev -type f -perm -0002 -print 2>/dev/null")
        world_writable_files = result.strip().split('\n')
        findings.extend(['World-writable file: ' + f for f in world_writable_files if f])

        # World-writable directories
        result = subprocess.getoutput("find / -xdev -type d -perm -0002 -print 2>/dev/null")
        world_writable_dirs = result.strip().split('\n')
        findings.extend(['World-writable directory: ' + d for d in world_writable_dirs if d])

        # SUID/SGID files
        result = subprocess.getoutput("find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null")
        suid_sgid_files = result.strip().split('\n')
        findings.extend(['SUID/SGID file: ' + f for f in suid_sgid_files if f])
    except Exception as e:
        logging.error(f'Error checking file permissions: {e}')
        findings.append(f'Error checking file permissions: {e}')
    return findings


def generate_graphs(df, timestamp):
    """Generate graphs for the report."""
    try:
        # Count of findings by category
        category_counts = df['Category'].value_counts()
        plt.figure(figsize=(10, 6))
        sns.barplot(x=category_counts.index, y=category_counts.values, palette='viridis')
        plt.title('Number of Findings by Category')
        plt.xlabel('Category')
        plt.ylabel('Number of Findings')
        plt.xticks(rotation=45)
        plt.tight_layout()
        graph_filename = f'findings_by_category_{timestamp}.png'
        plt.savefig(graph_filename)
        plt.close()
    except Exception as e:
        logging.error(f'Error generating graphs: {e}')


def create_html_report(df, timestamp):
    """Create an HTML report using Jinja2 templates."""
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')

        html_content = template.render(
            timestamp=timestamp,
            findings=df.to_dict(orient='records'),
            graph_filename=f'findings_by_category_{timestamp}.png'
        )
        report_filename = f'misconfig_report_{timestamp}.html'
        with open(report_filename, 'w') as f:
            f.write(html_content)
        return report_filename
    except Exception as e:
        logging.error(f'Error creating HTML report: {e}')
        return None


def generate_pdf_report(html_report_filename, timestamp):
    """Convert HTML report to PDF using WeasyPrint."""
    try:
        pdf_filename = f'misconfig_report_{timestamp}.pdf'
        HTML(html_report_filename).write_pdf(pdf_filename, stylesheets=[CSS(string='body { font-family: Arial; }')])
        logging.info(f'PDF report generated: {pdf_filename}')
        return pdf_filename
    except Exception as e:
        logging.error(f'Error generating PDF report: {e}')
        return None


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Linux Misconfiguration Detection Tool')
    parser.add_argument('-c', '--config', help='Specify a configuration file', default='config.ini')
    parser.add_argument('-o', '--output', help='Specify an output directory', default='.')
    parser.add_argument('-l', '--log', help='Specify a log file', default='misconfig_detector.log')
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Update logging to use the specified log file
    logging.getLogger().handlers[0].baseFilename = args.log

    config = load_config(args.config)

    all_findings = []

    # SSH Checks
    ssh_findings = check_ssh_config(config)
    for finding in ssh_findings:
        all_findings.append({
            'Category': 'SSH',
            'Finding': finding,
            'Severity': 'High' if 'root' in finding.lower() or 'protocol 1' in finding.lower() else 'Medium',
            'Recommendation': 'Review SSH configuration and disable insecure settings.'
        })

    # FTP Checks
    ftp_findings = check_ftp_config(config)
    for finding in ftp_findings:
        all_findings.append({
            'Category': 'FTP',
            'Finding': finding,
            'Severity': 'High',
            'Recommendation': 'Disable anonymous FTP login.'
        })

    # Web Server Checks
    web_findings = check_web_server_config(config)
    for finding in web_findings:
        all_findings.append({
            'Category': 'Web Server',
            'Finding': finding,
            'Severity': 'Medium',
            'Recommendation': 'Disable directory listing in web server configuration.'
        })

    # Outdated Packages
    package_findings = check_outdated_packages()
    for pkg in package_findings:
        all_findings.append({
            'Category': 'Outdated Packages',
            'Finding': pkg,
            'Severity': 'Medium',
            'Recommendation': 'Update the package to the latest version.'
        })

    # Unwanted File Permissions
    permissions_findings = check_unwanted_file_permissions()
    for finding in permissions_findings:
        severity = 'High' if 'SUID' in finding or 'SGID' in finding else 'Medium'
        all_findings.append({
            'Category': 'File Permissions',
            'Finding': finding,
            'Severity': severity,
            'Recommendation': 'Adjust file permissions to secure settings.'
        })

    # Convert findings to DataFrame
    df = pd.DataFrame(all_findings)

    # Generate timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Generate Graphs
    generate_graphs(df, timestamp)

    # Generate HTML Report
    html_report_filename = create_html_report(df, timestamp)

    # Generate PDF Report
    if html_report_filename:
        generate_pdf_report(html_report_filename, timestamp)
    else:
        logging.error('HTML report was not generated; skipping PDF report generation')

    print('Report generation complete. Check the output directory for the report files.')


if __name__ == '__main__':
    main()
