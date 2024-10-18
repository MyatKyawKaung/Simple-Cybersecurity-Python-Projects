import requests
import time
import sys
import argparse
import os

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

# Function to extract vendor detection information
def get_vendor_detections(scans: dict) -> str:
    identified_vendors = []
    
    for vendor, result in scans.items():
        if result.get('detected'):
            identified_vendors.append(f"- {vendor}: {result.get('result')}")
    
    if not identified_vendors:
        return "No vendors detected the URL as malicious."
    
    return "\n".join(identified_vendors)

# Main function for argument parsing and workflow control
def main():
    # Argument parser for command-line inputs
    parser = argparse.ArgumentParser(description="VirusTotal URL Checker")
    parser.add_argument('-o', '--output', required=True, help="Output file path (e.g., /path/to/output.txt)")
    parser.add_argument('-u', '--url', required=True, help="URL to scan (e.g., www.google.com)")
    parser.add_argument('-k', '--apikey-file', required=True, help="Path to the file containing the VirusTotal API key")
    
    args = parser.parse_args()

    # Get the API key from the specified file
    api_key = get_api_key(args.apikey_file)
    
    # Check the URL against VirusTotal
    response_json = check_url(api_key, args.url)
    
    if response_json is None:
        print("No valid response received from VirusTotal.")
        sys.exit(1)
    
    # Check if the URL is found and analyze the results
    if response_json.get('response_code') == 0:
        print(f"URL '{args.url}' not found in VirusTotal.")
        return
    
    positives = response_json.get('positives', 0)
    total = response_json.get('total', 0)
    scans = response_json.get('scans', {})
    
    # Get the vendor detection information
    vendor_detections = get_vendor_detections(scans)
    
    # Determine the result based on the number of positives
    if positives == 0:
        result = f"This Domain '{args.url}' is not likely to be malicious (0/{total} detections)"
    elif positives <= 3:
        result = f"This Domain '{args.url}' could potentially be MALICIOUS. ({positives}/{total} detections)"
    else:
        result = f"This Domain '{args.url}' is highly likely to be MALICIOUS ({positives}/{total} detections)"
    
    # Print and save the result to the output file
    print(result)
    print(f"Vendor Detections:\n{vendor_detections}")
    
    with open(args.output, 'a') as output_file:
        output_file.write(result +'\n')
        output_file.write(f"Vendor Detections:\n{vendor_detections}\n")

    time.sleep(15)  # Sleep for 15 seconds before making the next request, if needed

if __name__ == '__main__':
    main()