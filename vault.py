import base64
import json
import time

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
import binascii
import uuid
import pyotp

from termcolor import colored


def register_vault(name, location):
    """
    Places the vault in the config.json so it can be seen by the program on launch
    :param name: Name of the vault
    :param location: Path to the vault root
    """
    with open("config.json", "r") as f:
        config = json.load(f)
    with open("config.json", "w") as f:
        config["vaults"].append({"name": name, "location": location})
        json.dump(config, f)


"""
Version 0.4 added separate pin and pass timeouts
"""
LATEST = "0.4"


class Vault:
    """
    Vault class is responsible for generating and storing Vault data.
    Contains methods for creating and manipulating a vault and the items stored
    """
    __salt = None
    __vault_data = None
    __hash = None
    __uuid = None
    __pin_timeout = 65400  # dummy
    __pass_timeout = 30 * 60  # dummy
    __pin_enabled = None
    __root_path = None
    __password = None
    __files = None
    __dir_salt = None
    __last_pass = None
    __2fa_enabled = None
    __2fa_key = "AD5E6C8P4NYP4RFGIOJGUBXGSQKVLXZN"  # dummy, obfuscates if this is enabled or not (matches key length)
    __pin_set = False

    def __init__(self, path, open_vault=False):
        self.__root_path = path

        if open_vault:
            with open(Path(self.__root_path).joinpath("vault.json"), "r") as f:
                self.__vault_data = json.load(f)
                self.__salt = base64.b64decode(self.__vault_data["salt"])
                self.__uuid = self.__vault_data["uuid"]
                if self.__vault_data["version"] != LATEST:
                    raise Exception("Vault version not supported")

        self.sec_bytes = 256

        self.__hash = SHA3_256

    def lock(self):
        """
        invalidates the last login
        """
        self.__last_pass = -1.0

    def reauthenticate(self, password):
        """
        Sets password namespace for the vault. Immediately hashes and stores the hash rather than plaintext
        :param password: The password encoded as bytes
        """
        __password2 = self.__hash.new(self.__salt).update(password).hexdigest()
        if __password2 == self.__password:
            self.__last_pass = time.monotonic()
            return True
        else:
            self.__last_pass -= 30  # removes 10 seconds from the last password, requiring password sooner
            return False

    def unlock(self):
        """
        Unlocks the vault with the given initialization information
        """
        if self.__vault_data["verification"] == self.__hash.new(binascii.unhexlify(self.__password)).hexdigest():
            # Password correct, verify 2fa
            if (self.__vault_data["enable_2fa"] !=
                    self.__hash.new(binascii.unhexlify(self.__password)).update(bytes(str(True), 'utf-8')).hexdigest()):
                return self.__open_vault()
            else:
                return "2FA"
        else:
            return False

    def unlock_2fa(self, _2fa):
        """
        Unlocks the vault with the given initialization information, plus 2fa
        :param _2fa: the 6 digit 2FA number
        :return: if the vault was unlocked
        """
        try:
            if self.unlock() == "2FA":
                totp_verify = pyotp.TOTP(
                    unpad(
                        AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                        .decrypt(base64.b32decode(self.__vault_data["2fa_key"])),
                        AES.block_size).decode('utf8'),
                    6)
                print(totp_verify.secret)
                if totp_verify.verify(_2fa):
                    self.__open_vault()
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            print(e)
            exit(-1)

    def __open_vault(self):
        """
        Opens the vault with the given initialization information
        """
        # I'm keeping this last verification if someone accidentally gets this far
        if self.__vault_data["verification"] == self.__hash.new(binascii.unhexlify(self.__password)).hexdigest():
            # success, load other __vault_data objects
            self.__pin_enabled = (self.__vault_data["enable_pin"] ==
                                  self.__hash.new(binascii.unhexlify(self.__password))
                                  .update(bytes("True", 'utf-8')).hexdigest())
            self.__pin_timeout = int.from_bytes(unpad(
                AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                .decrypt(base64.b64decode(self.__vault_data["pin_timeout"])), AES.block_size))
            self.__pass_timeout = int.from_bytes(unpad(
                AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                .decrypt(base64.b64decode(self.__vault_data["pass_timeout"])), AES.block_size))
            self.__dir_salt = (AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                               .decrypt(base64.b64decode(self.__vault_data["dir_salt"])))
            self.__read_dir()
            self.__last_pass = time.monotonic()
            return True
        else:
            return False

    def create_vault(self):
        """
        Creates a new vault based on values from initialization and password retrieval. Creates the vault.json file
        """
        with open(Path(self.__root_path).joinpath("vault.json"), "w") as f:
            self.__vault_data = {
                # plain text
                "version": LATEST,
                # plain text
                "uuid": uuid.uuid4().hex,
                # plain text
                "salt": base64.b64encode(self.__salt).decode('utf-8'),
                # plain text
                "bit_security": self.sec_bytes,
                # plain text
                "verification": self.__hash.new(binascii.unhexlify(self.__password)).hexdigest(),
                # Obfuscated
                "enable_pin":
                    self.__hash.new(binascii.unhexlify(self.__password))
                    .update(bytes(str(self.__pin_enabled), 'utf-8')).hexdigest(),
                # Obfuscated
                "enable_2fa":
                    self.__hash.new(binascii.unhexlify(self.__password))
                    .update(bytes(str(self.__2fa_enabled), 'utf-8')).hexdigest(),
                # Encrypted
                "2fa_key":
                    base64.b32encode(AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                                     .encrypt(pad(bytes(self.__2fa_key, 'utf-8'), AES.block_size))).decode("utf-8"),
                # Encrypted
                "pass_timeout":
                    base64.b64encode(AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                                     .encrypt(pad(int.to_bytes(self.__pass_timeout, 2, 'big'),
                                                  AES.block_size)))
                    .decode("utf-8"),
                # Encrypted
                "pin_timeout":
                    base64.b64encode(AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                                     .encrypt(pad(int.to_bytes(self.__pin_timeout, 2, 'big'),
                                                  AES.block_size)))
                    .decode("utf-8"),
                # Nonce encrypted with ECB
                "dir_salt": None,
                # Encrypted
                "dir": {"root": []},
                # plaintext pk for GCM
                "nonce": None,
                # tag for GCM
                "tag": None
            }
            self.__uuid = self.__vault_data["uuid"]
            self.__salt = self.__vault_data["salt"]
            self.__write_vault()
            self.__last_pass = time.monotonic()

            register_vault(Path(self.__root_path).parts[-1], str(Path(self.__root_path).parent.absolute()))

    def __read_dir(self):
        if self.__vault_data["dir"] is None:
            self.__files = {"root": []}
            return

        cipher = AES.new(self.__hash.new(binascii.unhexlify(self.__password)).update(self.__dir_salt).digest(),
                         AES.MODE_GCM,
                         nonce=binascii.unhexlify(self.__vault_data["nonce"]))
        try:
            dtext = cipher.decrypt_and_verify(binascii.unhexlify(self.__vault_data["dir"]),
                                              binascii.unhexlify(self.__vault_data["tag"]))
            self.__files = json.loads(dtext)
        except ValueError:
            print(colored(f"Vault directory could not be decrypted: {ValueError('MAC check failed')}", 'red'))
            exit(1)

    def __write_vault(self):
        self.__dir_salt = get_random_bytes(16)
        self.__vault_data["dir_salt"] = base64.b64encode(AES.new(binascii.unhexlify(self.__password), AES.MODE_ECB)
                                                         .encrypt(self.__dir_salt)).decode("utf-8")

        cipher = AES.new(self.__hash.new(binascii.unhexlify(self.__password)).update(self.__dir_salt).digest(),
                         AES.MODE_GCM)
        ctext, tag = cipher.encrypt_and_digest(bytes(json.dumps(self.__files), "utf-8"))
        nonce = cipher.nonce
        self.__vault_data["dir"] = binascii.hexlify(ctext).decode()
        self.__vault_data["tag"] = binascii.hexlify(tag).decode()
        self.__vault_data["nonce"] = binascii.hexlify(nonce).decode()

        with open(Path(self.__root_path).joinpath("vault.json"), "w") as f:
            f.write(json.dumps(self.__vault_data))

    def update_password(self, password, pin):
        """
        Sets password namespace for the vault. Immediately hashes and stores the hash rather than plaintext
        :param pin: pin for authentication
        :param password: The password encoded as bytes
        """
        auth = self.is_authenticated(pin=pin, level=3)
        if auth == "__PIN__" or not auth:
            return auth
        if not self.__salt:
            self.__salt = get_random_bytes(16)

        self.__password = self.__hash.new(self.__salt).update(password).hexdigest()

    def set_pin(self, pin):
        if not pin:
            return False
        auth = self.is_authenticated(pin=pin, level=3)
        if auth == "__PIN__" or not auth:
            return auth

        self.__password = binascii.hexlify(
            bytes(a ^ b for a, b in zip(
                self.__hash.new(self.__salt).update(pin).digest(), binascii.unhexlify(self.__password)))
        )
        return True


    def set_password(self, password):
        """
        Sets password namespace for the vault. Immediately hashes and stores the hash rather than plaintext
        :param password: The password encoded as bytes
        """
        if not self.__salt:
            self.__salt = get_random_bytes(16)

        self.__password = self.__hash.new(self.__salt).update(password).hexdigest()

    def confirm_password(self, password):
        """
        Tests the password hash in memory against the inputted
        :param password: Password to test against the inputted password, hashes are compared
        :return: Boolean if the password matches
        """
        if not self.__salt:
            self.__salt = get_random_bytes(16)
        __password2 = self.__hash.new(self.__salt).update(password).hexdigest()
        return __password2 == self.__password

    def enable_pin(self, yes, pin=None):
        """
        Sets the vault pin enabled flag
        :param pin: to Authenticate
        :param yes: Boolean to enable pin
        """
        auth = self.is_authenticated(pin=pin, level=2)
        if auth == "__PIN__" or not auth:
            return auth
        self.__pin_enabled = yes is True
        return True

    def enable_2fa(self, yes, secret, pin=None):
        """
        Sets the vault pin enabled flag
        :param pin: pin to authenticate
        :param secret: Shared secret of 2fa system
        :param yes: Boolean to enable pin
        """

        auth = self.is_authenticated(pin=pin, level=2)
        if auth == "__PIN__" or not auth:
            return auth

        self.__2fa_enabled = yes is True
        self.__2fa_key = secret

    def set_pass_timeout(self, num, pin=None):
        """
        Sets the vault timeout value
        :param pin: pin for authentication
        :param num: number of seconds before timeout
        """
        auth = self.is_authenticated(pin=pin, level=2)
        if auth == "__PIN__" or not auth:
            return auth

        if num < 0:
            self.__pass_timeout = 0
        elif num > 2 ** 16 - 1:
            self.__pass_timeout = 65535
        else:
            self.__pass_timeout = num

    def set_pin_timeout(self, num, pin=None):
        """
        Sets the vault timeout value
        :param pin: pin for authentication
        :param num: number of seconds before timeout
        """
        auth = self.is_authenticated(pin=pin, level=2)
        if auth == "__PIN__" or not auth:
            return auth

        if num < 0:
            self.__pin_timeout = 0
        elif num > 2 ** 16 - 1:
            self.__pin_timeout = 65535
        else:
            self.__pin_timeout = num

    def is_authenticated(self, pin=None, level=1):
        """
        Tests authentication of the user
        :param pin: optional pin to test
        :param level: optional level of authentication
        :return: Boolean if the user is authenticated
        """
        now = time.monotonic()
        if not self.__last_pass:  # This is only true when creating a vault
            return True
        # 1 is recent password, 2 is pin required, 3 is password required
        # check if the user has recently entered password
        if now - self.__last_pass > self.__pass_timeout:
            return False
        if level == 1:
            # within 5 minutes which is a standard sudo session
            return now - self.__last_pass < min(self.__pass_timeout, 300)
        elif level == 2 and self.__pin_enabled and self.__pin_set:
            # If pin wasn't provided
            if not pin:
                return "__PIN__"
            else:
                # self.__vault_data["verification"]) = self.__hash.new(binascii.unhexlify(self.__password)).hexdigest()

                # Allows the user to set pin timeout to 0 to prevent the pin from expiring before the password
                time_check = now - self.__last_pass < self.__pin_timeout if self.__pin_timeout != 0 else True
                # when pin is enabled, __password is combined with hash of pin through xor and save to __password
                # this combines __password with pin through xor again... thus __password ^ pin ^ pin = verification
                combined = binascii.hexlify(
                    bytes(a ^ b for a, b in zip(
                        self.__hash.new(self.__salt).update(pin).digest(), binascii.unhexlify(self.__password)))
                )
                return (time_check and
                        self.__hash.new(binascii.unhexlify(combined)).hexdigest() == self.__vault_data["verification"])
        elif level == 2 or level == 3:  # if pin isn't enabled, we need a password anyways
            return now - self.__last_pass < 30  # within 30 sec
        else:
            return False

    def uuid(self):
        """
        Getter for the vault's uuid
        :return: the vault's uuid as a hexadecimal string
        """
        return self.__uuid

    def root(self):
        """
        Getter for the vault's root
        :return: the vault's root address
        """
        return self.__root_path
