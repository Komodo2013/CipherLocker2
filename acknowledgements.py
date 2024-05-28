import sys
from termcolor import colored


def show_acknowledgements_screen():
    """
    Shows license and disclaimer
    """
    # TODO: gui
    return


def cli_acknowledgements_screen():
    """
    Shows license and disclaimer
    """

    print("""LICENSE
    Icons by Icons8 at icons8.com
    
    MIT License
    
    Copyright (c) 2023 Cipher Locker Development Team
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
    documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
    permit persons to whom the Software is furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
    the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
    THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
    SOFTWARE.""")

    i = input(colored("Agree to license? (y/n): ", "yellow"))
    if i != "y":
        print(colored("Exiting!!! Please agree to the license\n", "red"))
        sys.exit()

    print("""DISCLAIMER
    Cipher Locker is a software project created as a practical learning experience. While we have made every effort to 
    design Cipher Locker with security in mind, please be aware that this application has yet to undergo professional 
    security testing, audits, or assessments. There may be unknown vulnerabilities with the program.  Cipher Locker 
    aims to provide a secure file vault where files are encrypted. However, it may contain vulnerabilities, and we 
    cannot guarantee its suitability for sensitive data or critical operations.
    
    User Responsibility:
    
    Users of Cipher Locker are advised to exercise caution and make informed decisions when using this software. It is 
    essential to remember that:
    
    \t*\tData Security: Cipher Locker employs AES-256 Encryption to protect your files. While this algorithm adequately 
    \t\tprotects data in theory, the specific implementation by the program or libraries may leave data vulnerable.
    \t*\tBackup: Always maintain regular backups of your data and files when using Cipher Locker or any other software 
    \t\tthat handles sensitive information.
    \t*\tRisk Acknowledgment: Users acknowledge and accept the potential risks associated with using Cipher Locker. 
    \t\tUsers assume full responsibility for their data and security by using this software.
    \t*\tNo Liability: Cipher Locker is proved "as is". The creators of Cipher Locker disclaim any liability for any 
    \t\tdirect or indirect damages, losses, or consequences arising from the use of this software. Users utilize Cipher 
    \t\tLocker at their own risk and discretion.
    \t*\tFeedback and Reporting: We encourage users to report any security concerns, vulnerabilities, or issues related 
    \t\tto Cipher Locker to help improve the software on our GitHub Page: https://github.com/liviis/CipherLock. 
    \t\tHowever, we do not guarantee immediate response or resolution.
    
    Conclusion:
    
    Cipher Locker is a learning project to gain practical experience. It should not be used as a primary or sole 
    solution for security-critical applications. Users are urged to use discretion and consider professional security 
    solutions for sensitive or mission-critical data.
    
    Thank you for your understanding and cooperation.
    
    
    
    Sincerely,
    
    \tCipher Locker Development Team
    """)

    i = input(colored("Agree to disclaimer? (y/n): ", "yellow"))
    if i != "y":
        print(colored("Exiting!!! Please agree to the disclaimer\n", "red"))
        sys.exit()

    return
