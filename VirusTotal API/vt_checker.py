import requests
import time
import sys
import argparse
import os
import csv
from datetime import datetime
import ipaddress

# Function to read the API key from a file
def get_api_key(file_path: str) -> str:
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    
    with open(file_path, 'r') as file:
        api_key = file.readline().strip()
        if not api_key:
            print("Error: API key file is empty.")
            sys.exit(1)
        return api_key

# Function to check the URL with VirusTotal
def check_url(api_key: str, url_to_scan: str) -> dict:
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url_to_scan}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to complete the request. {e}")
        return None

# Function to check the IP address with VirusTotal
def check_ip(api_key: str, ip_to_scan: str) -> dict:
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip_to_scan}
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to complete the request. {e}")
        return None

# Function to extract vendor detection information for URLs
def get_url_vendor_detections(scans: dict) -> str:
    identified_vendors = []
    
    for vendor, result in scans.items():
        if result.get('detected'):
            identified_vendors.append(f"- {vendor}: {result.get('result')}")
    
    if not identified_vendors:
        return "No vendors detected the URL as malicious."
    
    return "\n".join(identified_vendors)

# Function to extract detection information for IPs
def get_ip_detections(detected_urls: list) -> str:
    if not detected_urls:
        return "No malicious URLs associated with this IP."
    
    results = []
    for item in detected_urls[:5]:  # Limit to top 5 results
        results.append(f"- URL: {item['url']} (Detections: {item['positives']}/{item['total']})")
    
    # Add summary if there are more
    if len(detected_urls) > 5:
        results.append(f"... and {len(detected_urls) - 5} more malicious URLs")
    
    return "\n".join(results)

# Main function for argument parsing and workflow control
def main():
    # Argument parser for command-line inputs
    parser = argparse.ArgumentParser(description="VirusTotal Bulk URL/IP Checker")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-t', '--target', help="Single target to scan (URL or IP address)")
    input_group.add_argument('-i', '--input', help="Input file containing multiple targets (one per line)")
    parser.add_argument('-o', '--output', required=True, help="Output file path (e.g., results.txt)")
    parser.add_argument('-k', '--apikey-file', required=True, help="Path to file containing VirusTotal API key")
    parser.add_argument('--csv', action='store_true', help="Enable CSV output mode")
    parser.add_argument('--csv-output', help="Path to CSV output file (required if --csv is set)")
    parser.add_argument('--delay', type=float, default=15, help="Delay between requests in seconds (default: 15)")

    args = parser.parse_args()

    # Validate CSV arguments
    if args.csv and not args.csv_output:
        parser.error("--csv-output is required when using --csv")

    # Get targets from input file or single target
    targets = []
    if args.input:
        try:
            with open(args.input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(targets)} targets from {args.input}")
        except Exception as e:
            print(f"Error reading input file: {e}")
            sys.exit(1)
    else:
        targets = [args.target]

    # Get the API key
    api_key = get_api_key(args.apikey_file)
    
    # Open output files early to catch permission errors
    text_out = open(args.output, 'a')
    csv_out = None
    if args.csv:
        csv_out = open(args.csv_output, 'a', newline='', encoding='utf-8')
    
    # Process each target
    processed = 0
    for target in targets:
        processed += 1
        print(f"\nProcessing target {processed}/{len(targets)}: {target}")
        
        try:
            # Determine if target is IP or URL
            try:
                ipaddress.ip_address(target)
                is_ip = True
                resource_type = "ip"
            except ValueError:
                is_ip = False
                resource_type = "url"
            
            # Check the target against VirusTotal
            if is_ip:
                response_json = check_ip(api_key, target)
                scan_type = "IP"
            else:
                response_json = check_url(api_key, target)
                scan_type = "URL"
            
            if response_json is None:
                print(f"  [!] No valid response received for {scan_type}")
                continue
            
            # Check if the target is found
            if response_json.get('response_code') == 0:
                print(f"  [i] {scan_type} '{target}' not found in VirusTotal")
                continue
            
            # Process based on resource type
            if is_ip:
                # IP-specific processing
                detected_urls = response_json.get('detected_urls', [])
                malicious_count = len(detected_urls)
                scan_date = response_json.get('as_of', 'N/A')
                
                # Get detection information
                detections = get_ip_detections(detected_urls)
                
                # Determine risk level
                if malicious_count == 0:
                    result = f"IP '{target}' is not likely to be malicious (0 malicious URLs)"
                    risk_category = "Clean"
                elif malicious_count <= 3:
                    result = f"IP '{target}' could potentially be MALICIOUS. ({malicious_count} malicious URLs)"
                    risk_category = "Suspicious"
                else:
                    result = f"IP '{target}' is highly likely to be MALICIOUS ({malicious_count} malicious URLs)"
                    risk_category = "Malicious"
                    
                # For CSV
                positives = malicious_count
                total = 'N/A'
                vendor_detections = detections.replace('\n', ' | ')
            else:
                # URL-specific processing
                positives = response_json.get('positives', 0)
                total = response_json.get('total', 0)
                scans = response_json.get('scans', {})
                scan_date = response_json.get('scan_date', 'N/A')
                
                # Get detection information
                detections = get_url_vendor_detections(scans)
                vendor_detections = detections.replace('\n', ' | ')
                
                # Determine risk level
                if positives == 0:
                    result = f"URL '{target}' is not likely to be malicious (0/{total} detections)"
                    risk_category = "Clean"
                elif positives <= 3:
                    result = f"URL '{target}' could potentially be MALICIOUS. ({positives}/{total} detections)"
                    risk_category = "Suspicious"
                else:
                    result = f"URL '{target}' is highly likely to be MALICIOUS ({positives}/{total} detections)"
                    risk_category = "Malicious"
            
            # Print and save the result to the output file
            print(f"  [+] {result}")
            text_out.write(f"{result}\n")
            text_out.write(f"Detections:\n{detections}\n")
            text_out.write('-' * 50 + '\n\n')
            
            # Write to CSV if enabled
            if args.csv:
                csv_data = {
                    'resource_type': resource_type,
                    'target': target,
                    'scan_date': scan_date,
                    'positives': positives,
                    'total': total,
                    'risk_category': risk_category,
                    'detections': vendor_detections,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                writer = csv.DictWriter(csv_out, fieldnames=csv_data.keys())
                if csv_out.tell() == 0:  # Write header if new file
                    writer.writeheader()
                writer.writerow(csv_data)
        
        except Exception as e:
            print(f"  [!] Error processing {target}: {str(e)}")
        
        # Delay between requests
        if processed < len(targets):
            print(f"  [i] Waiting {args.delay} seconds before next request...")
            time.sleep(args.delay)
    
    # Close output files
    text_out.close()
    if csv_out:
        csv_out.close()
        print(f"\nCSV results saved to: {args.csv_output}")
    
    print(f"\nProcessing complete. {len(targets)} targets analyzed.")
    print(f"Text results saved to: {args.output}")

def write_csv(file_path, data):
    """Write results to CSV file with headers"""
    file_exists = os.path.isfile(file_path)
    
    with open(file_path, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['resource_type', 'target', 'scan_date', 'positives', 'total', 'risk_category', 'detections', 'timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(data)

if __name__ == '__main__':
    main()