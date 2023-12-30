#!/usr/bin/env python3

import argparse
import csv
import yaml
import json
import os

import gnupg

def data_from_decrypted_yaml(decrypted_data: str):
    password, _, remaining_data = decrypted_data.partition("\n")

    separated_data = remaining_data.split("---\n", 1)
    yaml_data = yaml.safe_load(separated_data[-1])
    username = None
    if yaml_data != None:
        username = yaml_data.get("user") or yaml_data.get("User") or yaml_data.get("username") or yaml_data.get("Username")

    return username, password

def get_password_data_from_gpg_files(gpg_files: [str], binary, agent):
        passwords = {}
        for file in gpg_files:
            default_username = file.name
            decrypted_data = decrypt(file, binary, agent)
            username, password = data_from_decrypted_yaml(decrypted_data["data"])
            username = username or default_username
            passwords[username] = password
        return passwords

def get_password_data(website_doc: str, binary, agent):
    website_name = ""
    passwords = {}
    if os.path.isdir(website_doc):
        website_name = os.path.basename(website_doc)
        passwords = get_password_data_from_gpg_files(os.scandir(website_doc), binary, agent)
    else:
        website_name = os.path.basename(website_doc).removesuffix(".gpg")
        passwords = get_password_data_from_gpg_files([website_doc], binary, agent)

    return {website_name: passwords}
    

def traverse(directory, binary, agent):
    websites = {}
    for website_dir in os.scandir(directory):
        website_data = get_password_data(website_dir, binary, agent)
        websites.update(website_data)

    return websites


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

    json_data = traverse(password_store, args.binary, args.agent)

    write(json_data, args.output)


if __name__ == '__main__':
    main()
