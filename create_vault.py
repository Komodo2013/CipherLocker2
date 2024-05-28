from pathlib import Path
from termcolor import colored
from getpass import getpass
from vault import Vault

import pyotp
import qrcode
from io import BytesIO
from PIL import Image


def show_create_vault(path):
    """
    Creates a vault at the specified path, GUI version
    :param path: The path of the vault you want to create
    """
    pass


def cli_create_vault(path):
    """
    Creates a vault at the specified path
    :param path: The path of the vault you want to create
    """

    # Ensure the root folder exists
    Path(path).mkdir(parents=True, exist_ok=True)

    print(colored("Please enter the name of the vault you want to create.", "yellow"))
    while True:
        vname = input()
        if vname != "":
            path = Path(path).joinpath(vname)  # Change root if we are adding a vault name
            path.mkdir(parents=True, exist_ok=True)
            break
        else:
            print(colored("Please enter a name.", "red"))

    vault = Vault(path)

    # Password verification
    while True:
        print(colored("Enter a password: ", "yellow"))
        vault.set_password(bytearray(getpass(), "utf-8"))
        print(colored("Confirm password: ", "yellow"))
        if vault.confirm_password(bytearray(getpass(), "utf-8")):
            break
        print(colored("Passwords did not match!\n", "red"))

    print("""
How long should the vault wait in seconds before the password expires and is required again? 
Range [0 - 65535] (Recommended 1800 = 30 minutes)
        """)
    while True:
        print(colored("Time in seconds: ", "yellow"))
        try:
            vault.set_pin_timeout(int(input()))
            break
        except ValueError:
            print(colored("Please enter an integer!\n", "red"))

    # Prompt for PIN capability, can be changed later
    print("""
This program asks for your password each time an authenticated change is requested, such as adding/removing/accessing 
files. A PIN can be configured to make this easier on you. The PIN can be the length of your choosing, but we 
suggest at least 4. All UTF-8 characters are allowed. This can be changed later.
    """)
    print(colored("Enable PINs? (y/n)", "yellow"))
    enable = input() is "y"  # default to False unless y is entered
    vault.enable_pin(enable)

    # This setting only applies to PIN lifetime
    if enable:
        print("""
How long should the vault wait in seconds before the PIN expires and the password is required again? 
If set to 0, the PIN expires when the password times out. 
Range [0 - 65535] (Recommended 300 = 5 minutes)
        """)
        while True:
            print(colored("Time in seconds: ", "yellow"))
            try:
                vault.set_pin_timeout(int(input()))
                break
            except ValueError:
                print(colored("Please enter an integer!\n", "red"))

    # Prompt for 2FA, can be changed later
    print("""
This program can enable 2Fa. PLEASE NOTE: if you loose your 2FA device you will not be able to log in. I have not
implemented a recovery OTP. ALSO: someone can edit this exe and disable 2FA checks by overwriting code. It does add
another layer of security, though, so as long as you don't loose your device, I would recommend this... just be careful.
    """)
    print(colored("Enable 2FA? (y/n)", "yellow"))
    enable = input() is "y"  # default to False unless y is entered

    if enable:

        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)

        uri = totp.provisioning_uri(name=vname, issuer_name="CipherLocker")
        qr = qrcode.main.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(uri)
        qr.make(fit=True)

        buffer = BytesIO()
        qr.make_image().save(buffer, 'png')
        buffer.seek(0)
        img = Image.open(buffer)
        img.show()

        for i in range(3):
            print(colored("Enter the OTP on your authenticator app: ", "yellow"))
            otp = input()

            if totp.verify(otp):
                print("2FA verified!")
                vault.enable_2fa(enable, totp.secret)
                break
            elif i == 3:
                print("Skipping 2FA, use sudo set --2fa to try again")
            else:
                print("Invalid code, try again.")

    #  Making vault file
    vault.create_vault()
    return vault
