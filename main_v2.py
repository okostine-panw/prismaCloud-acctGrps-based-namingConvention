from __future__ import print_function
import json
import requests
import configparser
import os
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

requests.packages.urllib3.disable_warnings()  # Added to avoid warnings in output if proxy


def return_error(message):
    print("\nERROR: " + message)
    exit(1)


def get_parser_from_sections_file(file_name):
    file_parser = configparser.ConfigParser()
    try:  # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError,
            configparser.DuplicateOptionError):
        return_error("Unable to read file " + file_name)
    return file_parser


def read_value_from_sections_file(file_parser, section, option):
    value = {}
    value['Exists'] = False
    if file_parser.has_option(section, option):  # Checks if section and option exist in file
        value['Value'] = file_parser.get(section, option)
        if not value['Value'] == '':  # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value


def read_value_from_sections_file_and_exit_if_not_found(file_name, file_parser, section, option):
    value = read_value_from_sections_file(file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']


def load_api_config(iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file(iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser, 'URL',
                                                                                'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found(iniFilePath, iniFileParser,
                                                                                  'AUTHENTICATION', 'SECRET_KEY')
    return api_config


def handle_api_response(apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error("API call failed with HTTP response " + str(status))


def run_api_call_with_payload(action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, data=json.dumps(payload),
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def run_api_call_without_payload(action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value,
                                   verify=False)  # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse


def login(api_config):
    action = "POST"
    url = api_config['BaseURL'] + "/login"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload(action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token


def get_account_groups(api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/cloud/group"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload(action, url, headers)
    accountGroups = json.loads(apiResponse.text)
    return accountGroups


def update_account_group(api_config, accountGroupName, accountGroupId, accountIds, description):
    action = "PUT"
    url = api_config['BaseURL'] + "/cloud/group/" + accountGroupId
    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': api_config['Token']
    }
    payload = {
        'accountIds': accountIds,
        'name': accountGroupName,
        'description': description
    }
    run_api_call_with_payload(action, url, headers, payload)


def get_accountGroupData_from_accountGroupList_by_name_equals(accountGroupName, accountGroupsList):
    accountGroupExists = False
    for accountGroup in accountGroupsList:
        if (accountGroup['name'].lower() == accountGroupName.lower()):
            accountGroupExists = True
            break
    if not accountGroupExists:
        return_error("Account Group \"" + accountGroupName + "\" does not exist")
    return accountGroup


def get_accountIds_from_accountGroup_by_name_contains(nameToSearch, accountGroupData):
    accountsMatching = []
    for account in accountGroupData['accounts']:
        if (nameToSearch.lower() in account['name'].lower()):
            accountsMatching.append(account)
    print("Number of Cloud Accounts matching \"" + nameToSearch + "\" in Account Group \"" + accountGroupData[
        'name'] + "\": " + str(len(accountsMatching)))
    if (len(accountsMatching) > 0):
        for account in accountsMatching:
            print("\t" + account['name'])
    return accountsMatching


def delete_item_from_list_if_exists(item, list):
    if item in list:
        list.remove(item)
    return list


def add_item_in_list_if_not_exists(item, list):
    if item not in list:
        list.append(item)
    return list


def delete_account_from_account_group(api_config, account, accountGroup):
    accountIds = delete_item_from_list_if_exists(account['id'], accountGroup['accountIds'])
    print("Deleting account \"" + account['name'] + "\" from Account Group \"" + accountGroup['name'] + "\"")
    update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])


def add_account_in_account_group(api_config, account, accountGroup):
    accountIds = add_item_in_list_if_not_exists(account['id'], accountGroup['accountIds'])
    print("Adding account \"" + account['name'] + "\" to Account Group \"" + accountGroup['name'] + "\"")
    update_account_group(api_config, accountGroup['name'], accountGroup['id'], accountIds, accountGroup['description'])


def move_account_from_source_to_destination_account_group(api_config, accountToMove, sourceAccountGroup,
                                                          destinationAccountGroup):
    delete_account_from_account_group(api_config, accountToMove, sourceAccountGroup)
    add_account_in_account_group(api_config, accountToMove, destinationAccountGroup)


def move_accounts_containing_name_from_source_to_destination_account_group(api_config, accountGroupsList,
                                                                           stringToSearchInAccounts,
                                                                           sourceAccountGroupName,
                                                                           destinationAccountGroupName):
    sourceAccountGroup = get_accountGroupData_from_accountGroupList_by_name_equals(sourceAccountGroupName,
                                                                                   accountGroupsList)
    destinationAccountGroup = get_accountGroupData_from_accountGroupList_by_name_equals(destinationAccountGroupName,
                                                                                        accountGroupsList)
    accountsToMove = get_accountIds_from_accountGroup_by_name_contains(stringToSearchInAccounts, sourceAccountGroup)
    for accountToMove in accountsToMove:
        if accountToMove['type'] == "gcp":
            print("Cloud Account \"" + accountToMove['name'] + "\" type is GCP, not moving it.")
        else:
            move_account_from_source_to_destination_account_group(api_config, accountToMove, sourceAccountGroup,
                                                                  destinationAccountGroup)


def main():


    # ----------- Load API configuration from .ini file -----------
    api_config = load_api_config("API_config.ini")

    # ----------- First API call for authentication -----------
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def authenticate_and_update_config(api_config):
        token = login(api_config)
        api_config['Token'] = token
        return api_config

    api_config = authenticate_and_update_config(api_config)

    # ----------- Get Account Groups -----------
    account_groups_list = get_account_groups(api_config)

    # ----------- Move Accounts from their current Account Group to another one -----------
    def batch_move_accounts(api_config, account_groups_list, move_instructions):
        for source_group, destination_group, account_type in move_instructions:
            move_accounts_containing_name_from_source_to_destination_account_group(
                api_config, account_groups_list, source_group, destination_group, account_type
            )

    move_instructions = [
        ("AzureAD", "Default Account Group", "Identity"),
        ("Identity", "Default Account Group", "Identity"),
        ("Access Management", "Default Account Group", "Identity"),
        ("Sandbox", "Default Account Group", "Sandbox"),
        ("Self-Managed", "Default Account Group", "Self-Managed"),
        ("Free Trial", "Default Account Group", "Free Trial"),
        ("DevOps", "Default Account Group", "DevOps"),
        ("CyberArk", "Identity", "CyberArk")
    ]

    batch_move_accounts(api_config, account_groups_list, move_instructions)


if __name__ == "__main__":
    main()