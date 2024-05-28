from getpass import getpass
import readline
import os
from termcolor import colored

from cli import CLI


def show_vault_ui(vault):
    """

    :param vault:
    """
    pass


def complete(cli):
    def inner(text, state):
        """
        Return the next possible completion for 'text'.
        This is called successively with state 0, 1, 2, ... until it returns None.
        """

        if text == "":
            return None

        matches = [command for command in cli.commands if command.startswith(text)]

        if text.startswith("$") and False:
            items = cli.parse(f"ls --as-array {cli.cwd_vault}")

            matches2 = [item for item in items if item.startswith(text)]
            matches.extend(matches2)
        else:
            # Get the list of files and directories in the current directory
            current_dir = os.getcwd()
            files = os.listdir(current_dir)

            # Filter the list to include only directories that start with 'text'
            matches2 = [file for file in files if file.startswith(text) and os.path.isdir(os.path.join(current_dir, file))]
            matches.extend(matches2)

        try:
            return matches[state]
        except IndexError:
            return None
    return inner

def cli_vault_ui(vault):
    """
    Manipulation of a vault using CLI interface
    :param vault: The opened vault instance
    """
    os.system('cls' if os.name == 'nt' else 'clear')

    vault_cli = CLI(vault)

    # Set the completion function
    readline.set_completer(complete(vault_cli))

    # Enable tab-completion
    readline.parse_and_bind("tab: complete")

    print(colored(f"Signed into vault {vault.uuid()} @ {vault.root()}\nFor assistance type 'help'", "magenta"))
    print(colored("To access the filesystem outside the vault, type '/' for absolute or '~' for relative\nTo access "
                  "the vault filesystem, type '$' for absolute or '#' for relative", "green"))

    while True:
        user_in = input(colored(f"{vault.uuid()}:", 'green')
                        + colored(f"{vault_cli.pwd(None)}|\t", 'blue'))
        try:
            result = vault_cli.parse(user_in)
            if result and result == "__PIN__":
                pin = getpass(colored(f"Enter PIN: ", 'yellow'))
                result = vault_cli.parse(user_in + f"--PIN-- {pin}")
            if result:
                print(result)
        except Exception as e:
            print(e)


def cli_open_vault(vault):
    """
    Attempts to open the vault with the designated root
    :param vault: Vault initiated with root path
    """

    print(colored("Enter a password: ", "yellow"))
    vault.set_password(bytearray(getpass(), "utf-8"))

    unlock = vault.unlock()

    if unlock == "2FA":
        print(colored("Enter 2FA code from your Authenticator App: ", "yellow"))
        if vault.unlock_2fa(input()):
            cli_vault_ui(vault)
        else:
            print(colored("Unable to sign you in", "red"))
            exit(0)
    elif unlock:
        cli_vault_ui(vault)
    else:
        print(colored("Incorrect password", "red"))
        exit(0)
