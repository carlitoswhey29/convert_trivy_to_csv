"""_summary_

    convert_trivy_to_csv.py
    ================
    
    This script formats the output of a trivy scan which used the command below,
    to remove all unicode and output the table into a csv format
    
    Shell:
        `trivy image --input <image:tag|filename.tar> > trivy-results.txt`
        
    Example:
        python convert_trivy_to_csv.py --input input.txt --output output.csv
        
"""

__author__ = "Carlos Aguilar"


import argparse
import re
from collections import defaultdict
import csv

# encoding constant
UTF_8 = 'utf-8'

def read_file(file_path):
    with open(file_path, 'r', encoding=UTF_8) as file:
        return file.readlines()
    
def write_csv_file(file_path, data):
    fieldnames = ['Library', 'Vulnerability', 'Severity', 'Status', 'Installed Version', 'Fixed Version', 'Title']
    header = True
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for library, vulnerabilities in data.items():
            if header:
                header = False
                continue
            for vuln in vulnerabilities:
                row = extract_vulnerability_info(library, vuln)
                writer.writerow(row)
    print(f"Completed Task.\nNew File: {file_path}")
    
def remove_unwanted_lines(lines):
    border_start = re.compile(r'^[┌├└]')
    border_end = re.compile(r'^.*[┐┤┘]$')
    cleaned_lines = []
    for line in lines:
        if not border_start.match(line) and not border_end.match(line):
            cleaned_lines.append(line)   
    return cleaned_lines

def replace_unicode_characters(lines):
    replaced_lines = []
    for line in lines:
        line = line.replace('│', '|')
        replaced_lines.append(line)
    return replaced_lines

def extract_vulnerability_info(library, vuln):
    return {
        'Library': library,
        'Vulnerability': vuln['vulnerability'],
        'Severity': vuln['severity'], 
        'Status': vuln['status'], 
        'Installed Version': vuln['installed_version'], 
        'Fixed Version': vuln['fixed_version'], 
        'Title': vuln['title']
    }
    
def extract_parts(line, delimiter='|'):
    parts = [part.strip() for part in line.split(delimiter)[1:-1]]
    return parts

def create_vulnerability(vulnerability, severity, status, installed_version, fixed_version, title):
    return {
        'vulnerability': vulnerability,
        'severity': severity,
        'status': status if status else '', 
        'installed_version': installed_version if installed_version else '',
        'fixed_version': fixed_version if fixed_version else '',
        'title': title if title else ''
    }
            
def update_current_vulnerability_title(current_vulnerability, title):
    if current_vulnerability:
        current_vulnerability['title'] += ' ' + title
    
def parse_table(lines):
    data = defaultdict(list)
    current_library = None
    current_vulnerability = None
    current_severity = None
    current_status = None

    for line in lines:
        if any(line.startswith(prefix) for prefix in ['| --- ', '|']):
            library, vulnerability, severity, status, installed_version, fixed_version, title = extract_parts(line)
            if library:
                current_library = library
                if not vulnerability:
                    vulnerability = current_vulnerability['vulnerability']
            if severity:
                current_severity = severity
            if status:
                current_status = status
            if vulnerability:
                current_vulnerability = create_vulnerability(
                    vulnerability, current_severity, current_status, installed_version, fixed_version, title
                )
                data[current_library].append(current_vulnerability)
            elif title:
                update_current_vulnerability_title(current_vulnerability, title) 
    return data

def parse_arguments():
    parser = argparse.ArgumentParser(description="Convert Trivy scan result text files to a more readable format.")
    parser.add_argument('--input', type=str, help='Path to the input text file containing Trivy scan results')
    parser.add_argument('-o','--output', type=str, help='Path to the output text file')

    return parser.parse_args()

# ==============================================================================
# Main
# ==============================================================================
def main():
    """
        Example:
            python convert_trivy_to_csv.py --input input.txt -o output.txt
    """
    args = parse_arguments()
    lines = read_file(args.input)
    lines = remove_unwanted_lines(lines)
    lines = replace_unicode_characters(lines)
    data = parse_table(lines)
    write_csv_file(args.output, data)
    
if __name__ == "__main__":
    main()
    
