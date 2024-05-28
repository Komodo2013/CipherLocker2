import json
import os

from termcolor import colored
from getpass import getpass


with open("man.json", "r") as f:
    man_pages = json.load(f)


def arg_parser(args):
    a = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            if i+1 < len(args) and args[i+1].startswith("--"):
                a.update({args[i]: True})
                i += 1
            elif i+1 < len(args):
                a.update({args[i]: args[i+1]})
                i += 2
            else:
                a.update({args[i]: True})
                i += 1
    return a

class CLI:
    """
    Provides interface with the vault through commands, also to be used by gui
    """
    commands = ["pwd", "exit", "sudo", "help", "man", "lock", "set"]
    functions = None
    cwd_vault = "$"
    cwd_system = "~"
    cwd_is_vault = True
    cwd_system_relative_root = None

    def __init__(self, vault):
        self.vault = vault
        self.functions = [self.pwd, self.exit, self.sudo, self.help, self.man, self.lock, self.set]
        self.cwd_system_relative_root = self.vault.root()

    def set(self, args):
        if (len(args) == 0 or "-h" in args or "--help" in args or
                args[0] not in ["--enable-pin", "--password", "--pin", "--timeout", "--2fa"]):
            print("""
set allows for changing vault settings. 
    --help see this list
    --enable-pin <True/False> enables/disables pin
    --password prompts for password reset
    --pin prompts for pin creation
    --pass_timout <second> sets the seconds until vault password times out
    --pin_timout <second> sets the seconds until vault pin times out
    --2fa prompts for 2fa creation
""")
            return
        args = arg_parser(args)

        for arg, value in args.items():
            if arg == "--enable-pin":
                if value == "True":

                    pin = getpass(colored("Set PIN: ", "green"))
                    cpin = getpass(colored("Confirm: ", "green"))

                    if pin == cpin:
                        r = self.vault.enable_pin(True)
                        if r == "__PIN__" or not r:
                            print(colored("Failed to authenticate, run with sudo", "red"))
                        else:
                            print(colored("PIN enabled", "green"))
                            r = self.vault.set_pin(bytearray(pin, "utf-8"))
                            if r == "__PIN__" or not r:
                                print(colored("Failed to authenticate, run with sudo", "red"))
                            else:
                                print(colored("PIN set", "green"))

                    del pin, cpin
                elif value == "False":
                    r = self.vault.enable_pin(False)
                    if r == "__PIN__":
                        r = self.vault.enable_pin(False, input(colored("Enter PIN:", "green")))
                        if r == "__PIN__" or not r:
                            print(colored("Failed to authenticate", "red"))
                        else:
                            print(colored("PIN disabled", "green"))
                else:
                    print(colored("Invalid value for --enable-pin", "red"))


    def lock(self, args):
        self.vault.lock()
        os.system('cls' if os.name == 'nt' else 'clear')
        print("Please sign back into vault: ")
        counter = 0

        while True:
            try:
                if not self.vault.reauthenticate(bytearray(getpass(), "utf-8")):
                    counter += 1
                    if counter >= 3:
                        print(colored("Failed to reauthenticate. This event will be reported", "red"))
                        exit(0)
                else:
                    break
            except Exception as e:
                print(e)
                exit(1)


    def man(self, args):
        if args[0] in man_pages.keys():
            print(colored(man_pages[args[0]], "light_grey"))
        else:
            print(colored(f"Function {args[0]} has no man page", "light_grey"))

    def help(self, args):
        """
        Prints a page of all available commands
        :param args: not used
        """
        print("""
Directories: 
    * '$' indicates a directory in the vault
    * '/' indicates a system directory 
    * '~' indicates a system directory relative to vault root

Commands:
    * cat   |   prints out the contents of a file
    * cd    |   changes the current directory
    * clutter   generates dummy folders and files
    * exit  |   exit the program
    * export|   copies and decrypts the file/folder to the system
    * find  |   searches a directory for a file
    * flag  |   sets a flag on the file/folder
    * grep  |   searches files in a directory for content patterns
    * help  |   show this help message
    * import|   copies and encrypts the file/folder to the vault
    * ls    |   list files and directories at the path
    * lock  |   locks the vault without exiting the program
    * man   |   shows the man page for the specified command
    * mv    |   moves the file or directory to the specified path
    * mkdir |   creates a new directory
    * open  |   opens a file with text editor or specified program
    * pwd   |   show the current working directory
    * rm    |   remove the specified file or directory
    * set   |   modifies vault settings and password
    * stat  |   shows the file/folder stats 
    * touch |   creates a new file

to report bugs/suggestions, please go to https://github.com/liviis/CipherLock/issues
""")

    def sudo(self, args):
        """
        Reauthenticates the user for authenticated commands
        :param args: the command to execute and its args
        """
        if not self.vault.reauthenticate(bytearray(getpass("Sudo password: "), "utf-8")):
            if not self.vault.reauthenticate(bytearray(getpass("Sudo password: "), "utf-8")):
                if not self.vault.reauthenticate(bytearray(getpass("Sudo password: "), "utf-8")):
                    print(colored("Failed to reauthenticate. This event will be reported", "red"))
                    return
        self.parse(" ".join(arg for arg in args))

    def pwd(self, args):
        """
        Provides the current working directory
        :param args: -h or --help for help
        :return: current working directory
        """
        if args and ("-h" in args or "--help" in args):
            print("""
pwd will print the current working directory. 
A '$' indicates that the current working directory is within the vault.
A '~' or '/' indicates that the current directory is a system path.
'~' indicates that the current directory is relative to the vault root.
""")

        if self.cwd_is_vault:
            return colored(self.cwd_vault, "blue")
        else:
            return colored(self.cwd_system, "blue")

    def exit(self, args):
        """
        Exits the program
        :param args: not used
        """
        print(colored("Goodbye!", "cyan"))
        exit(0)

    def parse(self, user_in):
        """
        gets the command inputted from the user and calls the function
        :param user_in:
        """
        words = user_in.split()
        if len(words) == 1:
            words.append(None)
        for c in range(len(self.commands)):
            if words[0] == self.commands[c]:
                return self.functions[c](words[1:])
        print(colored(f"Unknown command: {words[0]}", "red"))
