import glob
import json
import argparse

def print_request_parameters(json_data, file_path, user_agent_filter=None, source_ip_filter=None):
    event_name = json_data.get("eventName")
    
    if user_agent_filter and user_agent_filter not in str(json_data.get("userAgent", "")):
        return

    if source_ip_filter and source_ip_filter not in str(json_data.get("sourceIPAddress", "")):
        return
    
    if event_name == "CreateKeyPair":
        request_parameters = json_data.get("requestParameters")
        response_elements = json_data.get("responseElements")
        if request_parameters and isinstance(request_parameters, dict):
            print(f"Found '\033[92mCreateKeyPair\x1b[0m' in {file_path}\n")
            print(f"Request parameters: {request_parameters}\n")
            print(f"Response elements {response_elements}") 
            print("\n" + '\033[31m' + "*"*100 + '\x1b[0m' + "\n")

    for key, value in json_data.items():
        if isinstance(value, dict):
            print_request_parameters(value, file_path, user_agent_filter, source_ip_filter)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    print_request_parameters(item, file_path, user_agent_filter, source_ip_filter)

def print_security_groups(json_data, file_path):
    event_name = json_data.get("eventName")
    if event_name == "CreateSecurityGroup":
        request_parameters = json_data.get("requestParameters")
        if request_parameters and isinstance(request_parameters, dict):
            print(f"Found '\033[92mCreateSecurityGroup\x1b[0m' in {file_path}\n")
            print(f"Request parameters: {request_parameters}") 
            print("\n" + '\033[31m' + "*"*100 + '\x1b[0m' + "\n")

    for key, value in json_data.items():
        if isinstance(value, dict):
            print_security_groups(value, file_path)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    print_security_groups(item, file_path)

def print_running_instances(json_data, file_path):
    event_name = json_data.get("eventName")
    if event_name == "RunInstances" or event_name == "StartInstances":
        request_parameters = json_data.get("requestParameters")
        if request_parameters and isinstance(request_parameters, dict):
            print(f"Found '\033[92mRunInstances\x1b[0m' in {file_path}\n")
            print(f"Request parameters: {request_parameters}")
            print("\n" + '\033[31m' + "*"*100 + '\x1b[0m' + "\n")

    for key, value in json_data.items():
        if isinstance(value, dict):
            print_running_instances(value, file_path)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    print_running_instances(item, file_path)

def count_source_ip_addresses(json_data, file_path, ip_address_counts):
    source_ip_address = json_data.get("sourceIPAddress")
    if source_ip_address:
        if source_ip_address in ip_address_counts:
            ip_address_counts[source_ip_address] += 1
        else:
            ip_address_counts[source_ip_address] = 1

    for key, value in json_data.items():
        if isinstance(value, dict):
            count_source_ip_addresses(value, file_path, ip_address_counts)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    count_source_ip_addresses(item, file_path, ip_address_counts)

def count_user_agents(json_data, file_path, user_agent_counts):
    user_agent = json_data.get("userAgent")
    if user_agent:
        if user_agent in user_agent_counts:
            user_agent_counts[user_agent] += 1
        else:
            user_agent_counts[user_agent] = 1

    for key, value in json_data.items():
        if isinstance(value, dict):
            count_user_agents(value, file_path, user_agent_counts)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    count_user_agents(item, file_path, user_agent_counts)

def search_files(directory_path, file_pattern, json_files, user_agent_filter=None, source_ip_filter=None):
    ip_address_counts = {}
    user_agent_counts = {}
    
    for file_path in json_files:
        with open(file_path, 'r') as file:
            try:
                json_data = json.load(file)
                print_request_parameters(json_data, file_path, user_agent_filter, source_ip_filter)
                print_security_groups(json_data, file_path)
                print_running_instances(json_data, file_path)
                count_source_ip_addresses(json_data, file_path, ip_address_counts)
                count_user_agents(json_data, file_path, user_agent_counts)
            except json.JSONDecodeError:
                print(f"Error decoding JSON in file: {file_path}")

    if not user_agent_filter:
        sorted_ip_counts = sorted(ip_address_counts.items(), key=lambda x: x[1], reverse=True)
        print("Source IP Address Counts (Descending Order):\n")
        for ip_address, count in sorted_ip_counts:
            print(f"{ip_address}: {count}\n")
    
        print('\n' + '\033[31m' + '*'*100 + '\x1b[0m')
        
        sorted_user_agent_counts = sorted(user_agent_counts.items(), key=lambda x: x[1], reverse=True)
        print("\nUser-Agent Counts (Descending Order):\n")
        for user_agent, count in sorted_user_agent_counts:
            print(f"{user_agent}: {count}\n")

def find_string_in_files(directory_path, file_pattern, json_files, search_string):
    for file_path in json_files:
        with open(file_path, 'r') as file:
            try:
                json_data = json.load(file)
                if search_string in str(json_data):
                    print(f"Found '\033[92m{search_string}\x1b[0m' in file: {file_path}\n")
            except json.JSONDecodeError:
                print(f"Error decoding JSON in file: {file_path}")

if __name__ == "__main__": 
    print('CloudTrail IOC searcher\n')
    print('\033[31m' + '*'*100 + '\x1b[0m' + "\n")
    
    parser = argparse.ArgumentParser(description='CloudTrail IOC searcher')
    parser.add_argument('-f', metavar='<Target Directory>', help='Target Directory, E.G: -f CloudTrail/', required=True) 
    parser.add_argument('-ua', metavar='<User Agent Filter>', help='Filter by User Agent substring, E.G: -ua <string>', required=False)
    parser.add_argument('-ip', metavar='<Source IP Address Filter>', help='Filter by Source IP Address substring, E.G: -ip <string>', required=False)
    args = parser.parse_args()

    directory_path = args.f
    user_agent_filter = args.ua
    source_ip_filter = args.ip

    file_pattern = '*.json'
    json_files = glob.glob(f'{directory_path}/**/{file_pattern}', recursive=True)

    if user_agent_filter or source_ip_filter:
        find_string_in_files(directory_path, file_pattern, json_files, user_agent_filter or source_ip_filter)
    else:
        search_files(directory_path, file_pattern, json_files, user_agent_filter, source_ip_filter)