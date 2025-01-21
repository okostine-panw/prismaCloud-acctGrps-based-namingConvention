import json
import requests
import configparser
import os
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO)

def return_error(message):
    logging.error(message)
    exit(1)

def get_parser(file_name):
    parser = configparser.ConfigParser()
    try:
        parser.read(file_name)
    except configparser.Error as e:
        return_error(f"Error reading file {file_name}: {e}")
    return parser

def read_value(parser, section, option, file_name):
    if parser.has_option(section, option):
        value = parser.get(section, option)
        if value:
            return value
    return_error(f"Missing or empty value for '{section}:{option}' in {file_name}")

def load_api_config(file_path):
    if not os.path.exists(file_path):
        return_error(f"Config file {file_path} does not exist")
    parser = get_parser(file_path)
    return {
        'BaseURL': read_value(parser, 'URL', 'URL', file_path),
        'AccessKey': read_value(parser, 'AUTHENTICATION', 'ACCESS_KEY_ID', file_path),
        'SecretKey': read_value(parser, 'AUTHENTICATION', 'SECRET_KEY', file_path)
    }

def handle_response(response):
    if response.status_code != 200:
        return_error(f"API call failed with status {response.status_code}")

def api_call(action, url, headers, payload=None):
    response = requests.request(action, url, headers=headers, json=payload, verify=False)
    handle_response(response)
    return response

def login(api_config):
    url = f"{api_config['BaseURL']}/login"
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey']
    }
    response = api_call("POST", url, {'Content-Type': 'application/json'}, payload)
    return response.json()['token']

def get_account_groups(api_config):
    url = f"{api_config['BaseURL']}/cloud/group"
    headers = {'x-redlock-auth': api_config['Token']}
    response = api_call("GET", url, headers)
    return response.json()

def update_account_group(api_config, group_id, name, account_ids, description):
    url = f"{api_config['BaseURL']}/cloud/group/{group_id}"
    payload = {
        'accountIds': account_ids,
        'name': name,
        'description': description
    }
    headers = {
        'Content-Type': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    api_call("PUT", url, headers, payload)

def find_group_by_name(name, groups):
    for group in groups:
        if group['name'].lower() == name.lower():
            return group
    return_error(f"Account Group '{name}' not found")

def filter_accounts_by_name(fragment, accounts):
    return [acc for acc in accounts if fragment.lower() in acc['name'].lower()]

def modify_account_group(api_config, account, group, action):
    if action == 'delete':
        group['accountIds'] = [id for id in group['accountIds'] if id != account['id']]
        logging.info(f"Deleting account '{account['name']}' from group '{group['name']}'")
    elif action == 'add':
        if account['id'] not in group['accountIds']:
            group['accountIds'].append(account['id'])
            logging.info(f"Adding account '{account['name']}' to group '{group['name']}'")
    update_account_group(api_config, group['id'], group['name'], group['accountIds'], group['description'])

def move_accounts(api_config, groups, fragment, src_group_name, dest_group_name):
    src_group = find_group_by_name(src_group_name, groups)
    dest_group = find_group_by_name(dest_group_name, groups)
    accounts = filter_accounts_by_name(fragment, src_group['accounts'])
    for account in accounts:
        if account['type'] != 'gcp':
            modify_account_group(api_config, account, src_group, 'delete')
            modify_account_group(api_config, account, dest_group, 'add')
        else:
            logging.info(f"Skipping GCP account '{account['name']}'")

def main():
    api_config = load_api_config("API_config.ini")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def authenticate(api_config):
        api_config['Token'] = login(api_config)
        return api_config

    api_config = authenticate(api_config)
    account_groups = get_account_groups(api_config)

    move_instructions = [
        ("Azure", "AzureAD", "Default Account Group"),
        ("Identity", "Identity", "Default Account Group"),
        ("Access Management", "Access Management", "Default Account Group"),
        ("Sandbox", "Sandbox", "Default Account Group"),
        ("Self-Managed", "Self-Managed", "Default Account Group"),
        ("Free Trial", "Free Trial", "Default Account Group"),
        ("DevOps", "DevOps", "Default Account Group"),
        ("CyberArk", "CyberArk", "Identity")
    ]

    for src_regex, src_name, dest in move_instructions:
        move_accounts(api_config, account_groups, src_regex, src_name, dest)

if __name__ == "__main__":
    main()
