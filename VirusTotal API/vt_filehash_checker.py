import requests
import argparse
import sys
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

# Validate the input hash based on length (MD5, SHA-1, or SHA-256)
def validate_hash(hash_value: str) -> str:
    if len(hash_value) in [32, 40, 64]:
        return hash_value
    else:
        print("Error: Invalid hash length. It must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.")
        sys.exit(1)

# Send a request to VirusTotal to check the file hash
def virus_total_request(api_key: str, file_hash: str) -> dict:
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_hash}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Unable to connect to VirusTotal API (Status Code: {response.status_code}).")
        sys.exit(1)

# Parse the VirusTotal response and display vendors that detected the file as malicious
def process_response(response: dict, file_hash: str) -> str:
    response_code = response.get('response_code')
    
    if response_code == 0:
        return f"This file hash '{file_hash}' is not found in VirusTotal."
    
    positives = response.get('positives', 0)
    total_scans = response.get('total', 0)

    if positives == 0:
        result = f"This file hash '{file_hash}' is not malicious (0/{total_scans} positive hits)."
    else:
        result = f"This file hash '{file_hash}' is malicious ({positives}/{total_scans} positive hits)."
        
        # Include details about which vendors detected it as malicious
        result += "\nDetected Vendors:"
        scans = response.get('scans', {})
        for vendor, report in scans.items():
            if report['detected']:
                result += f"\n - {vendor}: {report['result']}"
    return result

# Save the result to an output file
def save_to_file(output_path: str, result: str):
    with open(output_path, 'a') as output_file:
        output_file.write(result + '\n')
    print(f"Result saved to {output_path}.")

# Main function for argument parsing and workflow control
def main():
    # Argument parser for command-line inputs
    parser = argparse.ArgumentParser(description="VirusTotal Hash Checker")
    parser.add_argument('-o', '--output', required=True, help="Output file path (e.g., /path/to/output.txt)")
    parser.add_argument('-H', '--hash', required=True, type=validate_hash, help="File hash (e.g., MD5, SHA-1, or SHA-256)")
    parser.add_argument('-k', '--apikey-file', required=True, help="Path to the file containing the VirusTotal API key")
    
    args = parser.parse_args()

    # Get the API key from the specified file
    api_key = get_api_key(args.apikey_file)

    # Send the request and process the response
    response = virus_total_request(api_key, args.hash)
    result = process_response(response, args.hash)

    # Print and save the result
    print(result)
    save_to_file(args.output, result)

# Entry point of the script
if __name__ == '__main__':
    main()