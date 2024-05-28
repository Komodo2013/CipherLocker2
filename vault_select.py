from pathlib import Path
from termcolor import colored


def show_vault_select(vaults):
    """
    Provided as a minimal control interface
    :param vaults: dictionary of vaults
    """
    # TODO: build gui
    print("showing welcome screen")


def cli_vault_select(vaults):
    """
    Provided as a minimal control interface
    :param vaults: dictionary of vaults
    """

    while True:
        print("To get started, please select a vault or select new vault:")

        i = 1
        if vaults is not None and len(vaults) > 0:
            for vault in vaults:
                print(f"{i}:\t{vault['name']}\t{vault['location']}")
                i += 1
        print(f"{i}:\tCreate new Vault")
        print(f"{i+1}+:\tExit")

        v = input(colored("\nVault:\t", "yellow"))
        try:
            if int(v) < i:
                return {"create": False,
                        "path": Path(vaults[int(v) - 1]["location"]).joinpath(vaults[int(v) - 1]["name"])}
            elif int(v) == i:
                path = input(colored("Path of new vault: ", "yellow"))
                if Path(path).exists():
                    return {"create": True, "path": Path(path)}
                else:
                    print(colored("Path does not exist"), "red")
            elif int(v) > i:
                exit(1)
            else:
                print(colored("Invalid vault\n"), "red")
        except ValueError:
            print(colored("Invalid vault (enter the index)\n"), "red")
