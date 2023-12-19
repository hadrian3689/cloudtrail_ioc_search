import glob
import json
import argparse

def print_request_parameters(json_data, file_path):
    event_name = json_data.get("eventName")
    if event_name == "CreateKeyPair":
        request_parameters = json_data.get("requestParameters")
        response_elements = json_data.get("responseElements")
        if request_parameters and isinstance(request_parameters, dict):
            print(f"Found 'CreateKeyPair' in {file_path}\n")
            print(f"Request parameters: {request_parameters}\n")
            print(f"Response elements {response_elements}") 
            print("\n" + "*"*100 + "\n")

    for key, value in json_data.items():
        if isinstance(value, dict):
            print_request_parameters(value, file_path)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    print_request_parameters(item, file_path)

def print_security_groups(json_data, file_path):
    event_name = json_data.get("eventName")
    if event_name == "CreateSecurityGroup":
        request_parameters = json_data.get("requestParameters")
        if request_parameters and isinstance(request_parameters, dict):
            print(f"Found 'CreateSecurityGroup' in {file_path}\n")
            print(f"Request parameters: {request_parameters}") 
            print("\n" + "*"*100 + "\n")

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
            print(f"Found 'RunInstances' in {file_path}\n")
            print(f"Request parameters: {request_parameters}")
            print("\n" + "*"*100 + "\n")

    for key, value in json_data.items():
        if isinstance(value, dict):
            print_running_instances(value, file_path)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    print_running_instances(item, file_path)

def search_files(directory_path,file_pattern,json_files):
    for file_path in json_files:
        with open(file_path, 'r') as file:
            try:
                json_data = json.load(file)
                print_request_parameters(json_data, file_path)
                print_security_groups(json_data, file_path) 
                print_running_instances(json_data, file_path)
            except json.JSONDecodeError:
                print(f"Error decoding JSON in file: {file_path}")

if __name__ == "__main__": 
    print('CloudTrail IOC searcher\n')
    print('*'*100 + "\n")
    parser = argparse.ArgumentParser(description='CloudTrail IOC searcher')
    parser.add_argument('-f', metavar='<Target Directory>', help='Target Directory, E.G: -f CloudTrail/', required=True)
    args = parser.parse_args()

    directory_path = args.f
    file_pattern = '*.json'
    json_files = glob.glob(f'{directory_path}/**/{file_pattern}', recursive=True)

    search_files(directory_path,file_pattern,json_files)