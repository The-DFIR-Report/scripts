#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
.SYNOPSIS
    Deobfuscates a given Interlock RAT PHP script and extracts embedded IP addresses and domains.

.DESCRIPTION
    This script reads a PHP file that contains strings obfuscated with hexadecimal 
    and octal escape sequences. It first decodes these strings into readable text 
    and then uses regular expressions to find and list all unique IPv4 addresses 
    and domain names found within the deobfuscated content, excluding a 
    predefined list of system-related files and domains.

.AUTHOR
    The DFIR Report

.DATE
    2025/07/13

.PARAMETER path
    Specifies the path to the obfuscated PHP file. This parameter is mandatory.

.EXAMPLE
    python Deobfuscate-PhpConfig.py --path "C:\\path\\to\\your\\obfuscated_script.cfg"
"""

import argparse
import re
import sys
from colorama import Fore, Style, init

def deobfuscate_and_extract(file_path):
    """
    Reads, deobfuscates, and extracts IPs/domains from the given file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at path: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)

    def deobfuscate_match(match):
        """Callback function to handle hex and octal replacement."""
        # Check if the hex group (group 1) was matched
        if match.group(1):
            hex_value = match.group(1)
            return chr(int(hex_value, 16))
        # Otherwise, the octal group (group 2) must have been matched
        else:
            octal_value = match.group(2)
            return chr(int(octal_value, 8))

    # Deobfuscate hexadecimal and octal escape sequences in a single pass
    deobfuscation_regex = r'\\x([0-9a-fA-F]{2})|\\([0-7]{1,3})'
    deobfuscated_content = re.sub(deobfuscation_regex, deobfuscate_match, content)

    # Regex to find both IPv4 addresses and domain names
    extraction_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+'
    matches = re.findall(extraction_regex, deobfuscated_content)

    # Define a list of specific strings to exclude from the results
    exclude_list = [
        'rundll32.exe',
        'nodejs.org',
        '3-win-x64.zip',
        'node.exe',
        'Security.Principal.WindowsIdentity',
        'Security.Principal.WindowsPrincipal',
        'Security.Principal.WindowsBuiltInRole',
        'powershell.exe'
    ]

    # Filter the matches and get unique results
    filtered_matches = [match for match in matches if match not in exclude_list]
    unique_matches = sorted(list(set(filtered_matches)))

    # Output the unique results in color
    if unique_matches:
        print(f"{Fore.CYAN}--- Found IPs and Domains in '{file_path}' ---{Style.RESET_ALL}")
        
        ip_regex = r'^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'

        for match in unique_matches:
            if re.match(ip_regex, match):
                print(f"{Fore.GREEN}{match}{Style.RESET_ALL}")
            else:
                print(f"{Fore.MAGENTA}{match}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No IPs or Domains found in the file: {file_path}{Style.RESET_ALL}")

def main():
    """
    Main function to parse arguments and run the script.
    """
    # Initialize colorama to work on Windows
    init()

    parser = argparse.ArgumentParser(
        description="Deobfuscates a PHP script to find IPs and domains.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python %(prog)s --path \"C:\\path\\to\\your\\obfuscated_script.cfg\""
    )
    parser.add_argument("-p", "--path", required=True, help="Path to the obfuscated PHP file.")
    args = parser.parse_args()
    
    deobfuscate_and_extract(args.path)

if __name__ == "__main__":
    main()
