#!/usr/bin/env python3

import argparse
import json
import os
import re
import datetime
import uuid

import yaml
import gnupg

JSON_DEFAULT = {
    "encrypted": False,
    "folders": [],
    "items": []
}

URI_DEFAULT = {
    "match": None,
    "uri": None
}

LOGIN_DEFAULT_DATA = {
    "fido2Credentials": [],
    "uris": [
    ],
    "username": None,
    "password": None,
    "totp": None
}

ITEM_DEFAULT_DATA = {
    "passwordHistory": None,
    "revisionDate": None,
    "creationDate": None,
    "deletedDate": None,
    "id": None,
    "organizationId": None,
    "folderId": None,
    "type": 1,
    "reprompt": 0,
    "name": None,
    "notes": None,
    "favorite": False,
    "login": None,
    "collectionIds": None
}

def data_from_decrypted_yaml(decrypted_data: str):
    password, _, remaining_data = decrypted_data.partition("\n")

    separated_data = remaining_data.split("---\n", 1)
    yaml_data = yaml.safe_load(separated_data[-1])
    username = None
    if yaml_data != None:
        username = yaml_data.get("user") or yaml_data.get("User") or yaml_data.get("username") or yaml_data.get("Username")

    return str(username), password

def get_password_data_from_gpg_files(gpg_files: [str], binary, agent):
        data = []
        for file in gpg_files:
            default_username = file.name
            decrypted_data = decrypt(file, binary, agent)
            username, password = data_from_decrypted_yaml(decrypted_data["data"])
            username = username or default_username
            data.append({"password": password, "username": username})
        return data

def format_url(url):
    if not re.match('(?:http|ftp|https)://', url):
        return 'https://{}'.format(url)
    return url

def create_uris(website):
    uri_dict = URI_DEFAULT.copy()
    uri_dict.update({"uri": format_url(website)})
    return [uri_dict]

def create_login(website, user_pw_dict):
    login = LOGIN_DEFAULT_DATA.copy()
    login.update(user_pw_dict)
    login.update({"uris": create_uris(website)})
    print(website, user_pw_dict["username"])
    return login

def create_item(website, user_pw_dict):
    item = ITEM_DEFAULT_DATA.copy()
    date = datetime.datetime.now(datetime.UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    item.update({"login": create_login(website, user_pw_dict)})
    item.update({"name": website})
    item.update({"revisionDate": date})
    item.update({"creationDate": date})
    item.update({"id": str(uuid.uuid4())})
    return item


def get_items_from_website_data(website_data_dict):
    items = []
    for website in website_data_dict:
        for user_pw_dict in website_data_dict[website]:
            items.append(create_item(website, user_pw_dict))

    return items
    

def get_password_data(website_doc: str, binary, agent):
    website_name = ""
    user_pws_list = {}
    if os.path.isdir(website_doc):
        website_name = os.path.basename(website_doc)
        user_pws_list = get_password_data_from_gpg_files(os.scandir(website_doc), binary, agent)
    else:
        website_name = os.path.basename(website_doc).removesuffix(".gpg")
        user_pws_list = get_password_data_from_gpg_files([website_doc], binary, agent)

    return {website_name: user_pws_list}
    

def traverse(directory, binary, agent):
    items = []
    for website_dir in os.scandir(directory):
        website_data = get_password_data(website_dir, binary, agent)
        website_items = get_items_from_website_data(website_data)
        items.extend(website_items)

    return items


def decrypt(path, binary, agent):
    gpg = gnupg.GPG(gpgbinary=binary,
                    use_agent=agent)
    decrypted = None

    file = os.path.splitext(path)[0]
    extension = os.path.splitext(path)[1]

    if extension == '.gpg':
        with open(path, 'rb') as gpg_file:
            decrypted = {
                'path': file,
                'data': str(gpg.decrypt_file(gpg_file))
            }

    return decrypted

def write(data, output_file):
    with open(output_file, 'w', newline='') as json_file:
        json_str = json.dumps(data, indent=4)
        json_file.write(json_str)

def get_json_data_from_items(items_filled):
    json_data = JSON_DEFAULT.copy()
    json_data.update({"items": items_filled})
    return json_data

def main():
    parser = argparse.ArgumentParser(description='Export password-store data to Bitwarden CSV format.')

    parser.add_argument('--directory', '-d', default='~/.local/share/gopass/stores/root/websites',
                        help='Directory of the password store.')
    parser.add_argument('--gpg-binary', '-b', dest='binary', default='/usr/bin/gpg',
                        help='Path to the GPG binary.')
    parser.add_argument('--output-file', '-o', dest='output', default='pass.json',
                        help='File to write the JSON in.')
    parser.add_argument('--gpg-agent', '-a', dest='agent', help='Use GPG agent.', action='store_true')

    args = parser.parse_args()

    password_store = os.path.expanduser(args.directory)

    items_filled = traverse(password_store, args.binary, args.agent)

    json_data = get_json_data_from_items(items_filled)

    write(json_data, args.output)


if __name__ == '__main__':
    main()

# TODO figure out which record is causing error and why
