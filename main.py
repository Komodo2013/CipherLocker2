from termcolor import colored
import json
from pathlib import Path

import create_vault
import vault_select
import acknowledgements
import argparse

import vault_ui
from vault import Vault

VERSION = "0.3"

# Print CLI headers
print(colored("""
   ______  _        __                _____                 __                   
 .' ___  |(_)      [  |              |_   _|               [  |  _               
/ .'   \\_|__ _ .--. | |--. .---. _ .--.| |      .--.  .---. | | / ].---. _ .--.  
| |      [  [ '/'`\\ | .-. / /__\\[ `/'`\\| |   _/ .'`\\ / /'`\\]| '' </ /__\\[ `/'`\\] 
\\ `.___.'\\| || \\__/ | | | | \\__.,| |  _| |__/ | \\__. | \\__. | |`\\ | \\__.,| |     
 `.____ .[___| ;.__[___]|__'.__.[___]|________|'.__.''.___.[__|  \\_'.__.[___]    
            [__|                                                                 
""", "cyan", attrs=["bold"]))
print("""
CipherLocker is a software project created as a practical learning experience. While we have made every effort to 
design CipherLocker with security in mind, please be aware that this application has yet to undergo professional 
security testing, audits, or assessments.

Usage: cipherlocker [options]

Options:
  --help                Show this help message and exit
  --nogui               Encrypt a file
  --accept-risks        Decrypt a file
  --path                Path to vault folder
  --create              Create a new vault with the given path
  --open                Open a vault with the given path  
""")

# Set the file path for the config file
CONFIG_FILE = "config.json"

# Check if the config file exists, if not create it with default values
if not Path(CONFIG_FILE).exists():
    config = {
        "version": "0.2",  # version 0.2 added versioning to the config file and included vaults array
        "enable_ui": False,
        "ignore_risks": False,
        "vaults": []
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

# Load the config file
with open(CONFIG_FILE) as f:
    config = json.load(f)

vaults = config["vaults"]

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--nogui", action="store_true", help="Run in console mode without GUI")
parser.add_argument("--accept-risks", action="store_true", help="Accept all risks and bypass warnings")
parser.add_argument("--path", help="Path to the vault folder")
parser.add_argument("--create", action="store_true", help="Path to the vault folder")
parser.add_argument("--open", action="store_true", help="Path to the vault folder")

args = parser.parse_args()

if args.nogui == "True":
    config["enable_ui"] = False  # The default is False because GUI is not created yet and likely won't for a while

show_risks = not (config["ignore_risks"] or args.accept_risks)
if show_risks:
    acknowledgements.cli_acknowledgements_screen()

vault_path = None or args.path
if not vault_path:
    values = vault_select.show_vault_select(vaults) if config["enable_ui"] else (
        vault_select.cli_vault_select(vaults))
    vault_path = values['path']
    create = values['create']

    if not Path(vault_path).exists() and not create:
        print(f"Vault path {vault_path} does not exist")
        exit(1)
    elif create or args.create:
        vault_ui.cli_vault_ui(create_vault.cli_create_vault(vault_path))

vault_path = Path(vault_path).absolute()
print(f"Working directory: {colored(vault_path, "blue")}")

if args.create:
    vault_ui.cli_vault_ui(create_vault.cli_create_vault(vault_path))
elif Path(vault_path).exists():
    vault_ui.cli_open_vault(Vault(vault_path, open_vault=True))
else:
    print(colored("The chosen locker doesn't exist!", "red"))
    exit(1)

print(colored("Thank you for using CipherLocker!!", "cyan"))
