#########################################################################################
#                                                                                       #
#      Cisco IOS CPA IPsec VPN Gateway Configuration Tool                               #
#      (c) 2016 Cisco Systems, Inc                                                      #
#                                                                                       #
#      Simple script to build a baseline IPsec VPN configuration in support             #
#      of the CESG CPA certification requirements. Provides configuration of the        #
#      basic Foundation or end-state cryptographic profiles.                            #
#                                                                                       #
#      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS              #
#      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT                #
#      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS                #
#      FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE                   #
#      COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,                      #
#      INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES               #
#      (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR               #
#      SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)               #
#      HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,              #
#      STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)                    #
#      ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED              #
#      OF THE POSSIBILITY OF SUCH DAMAGE.                                               #
#                                                                                       #
#      Requires Python 3.x and pyOpenSSL.                                               #
#                                                                                       #
#########################################################################################


import re
import OpenSSL
import sys
from contextlib import redirect_stdout
import getpass

# Functions for determining if the entered value is a valid IP address

def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 254, m.groups()))

def check_ip(message):
    while True:
        user_input = input(message)
        if is_valid_ip(user_input):
            break
        else:
            print("Invalid IP address, please try again.")
            continue
    return user_input

# Function for determining valid mask - Needs Fixing

def is_valid_mask(mask):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", mask)
    return bool(m) and all(map(lambda n: int(n) == 0 or int(n) == 255, m.groups()))

# Parse and validate supplied interface description.

def check_interface_num(interface):

    tunnel_source_num = ""

    # Strip off the interface number from the supplied string

    m = False
    for i, j in enumerate(interface):
        if str(j) == " ":
            tunnel_source_num = interface[i+1:]
            tunnel_source_num = tunnel_source_num.lstrip()
            break
        elif str(j).isdigit():
            tunnel_source_num = interface[i:]
            break

    # Check to make sure an interface number was actually supplied.

    if tunnel_source_num == "":
        return tunnel_source_num, m
    else:

        # If a number was supplied, parse it and make sure it matches a recognised format i.e. 0, 1/1 or 1/2/3.

        m = re.match("^([0-9]{1,2})?\/?([0-9]{1,2})([\/](?=[0-9])[0-9])?$", tunnel_source_num)
        if m:
            return tunnel_source_num, m
        elif not m:
            return tunnel_source_num, m

def write_basics(host, domain):

    # Write out basic hostname information

    print("hostname {0}".format(host))
    print("ip domain-name {0}\n!".format(domain))

def generate_keys(profile):

    # Depending on Foundation of End-State, generate an RSA or ECC Keypair

    if profile == "e":
        print("crypto key generate ec keysize 256 label {0}_cpa_keys".format(hostname))
    elif profile == "f" or "i":
        print("crypto key generate rsa general-keys label {0}_cpa_keys modulus 2048".format(hostname))

def build_trustpoint(hostname, profile, subject):

    # Generate the PKI Trustpoint Configuration

    print("crypto pki trustpoint cpa_ca")
    print(" enrollment terminal")
    if profile == "e":
        print(" eckeypair {0}_cpa_keys".format(hostname))
    elif profile == "f" or "i":
        print(" rsakeypair {0}_cpa_keys".format(hostname))
    print(" hash sha256")
    print(" subject-name {0}".format(subject))
    print(" revocation-check crl")
    print(" crl configure")
    print("   cache-timeout 720\n!")

def build_interim(profile_name):

    # Build the Interim ISAKMP and IPsec crypto profiles

    print("crypto isakmp policy 10")
    print(" encryption aes 128")
    print(" hash sha")
    print(" group 5")
    print(" lifetime 82400\n!")
    print("crypto ipsec transform-set interim esp-aes esp-sha-hmac\n!")
    print("crypto ipsec profile {0}".format(profile_name))
    print(" set transform-set interim")
    print(" set pfs group5\n!")


def build_foundation(profile_name):

    # Build the Foundation ISAKMP and IPsec crypto profiles

    print("crypto isakmp policy 10")
    print(" encryption aes 128")
    print(" hash sha256")
    print(" group 14")
    print(" lifetime 82400\n!")
    print("crypto ipsec transform-set foundation esp-aes esp-sha256-hmac\n!")
    print("crypto ipsec profile {0}".format(profile_name))
    print(" set transform-set foundation")
    print(" set pfs group14\n!")

def build_endstate(profile_name):

    # Build the end-state IKEv2 and IPsec crypto profiles

    print("crypto ikev2 proposal end_state_proposal")
    print(" encryption aes-gcm-128")
    print(" hash sha256")
    print(" group 19")
    print("crypto ikev2 profile end-state-profile")
    print(" authentication local ecdsa-sig")
    print(" authentication remote ecdsa-sig")
    print(" lifetime 82400")
    print(" match remote address any\n!")
    print("crypto ipsec transform-set end-state esp-gcm 128\n!")
    print("crypto ipsec profile {0}".format(profile_name))
    print(" set transform-set end-state")
    print(" set pfs group19")
    print(" set ikev2-profile end-state-profile\n")

def build_tunnel_interface(profile, tunnel_IP, tunnel_mask, tunnel_dst, tunnel_src_int, tunnel_src_num):

   # Create the tunnel interface and bind it to the supplied IPsec profile name

    print("interface tunnel1")
    print(" ip address {0} {1}".format(tunnel_IP, tunnel_mask))
    print(" tunnel source {0} {1}".format(tunnel_src_int, tunnel_src_num))
    print(" tunnel destination {0}".format(tunnel_dst))
    print(" tunnel protection ipsec profile {0}\n".format(profile))

# Print Final Instructions

def print_final(cert_supplied):
    if not cert_supplied:
            print("\nNow you will need to manually authenticate your router to the Certificate Authority by importing the CA certificate")
            print(
                "You can do this by issuing the \"crypto pki authenticate cpa_ca\" command and following the instructions\n")

    print("You will need to enroll your router in to the Certificate Authority")
    print("You can do this by performing a \"crypto pki enrol cpa_ca\" command and following the instructions\n")

# Dump out the supplied X509 CA Certificate to the CLI if it was supplied

def authenticate_trustpoint(c, ca_cert):

    cert_out = c.dump_certificate(c.FILETYPE_PEM, ca_cert)

    cert_out = cert_out.decode("utf-8")

    print("crypto pki authenticate cpa_ca")
    for line in cert_out.split("\n"):
        print(line)

# Load the supplied CA Certificate from the Command Line

def load_ca_cert(filename):

    try:
        with open(filename, 'rt') as f:
            st_cert = f.read()
            c = OpenSSL.crypto
            ca_certificate = c.load_certificate(c.FILETYPE_PEM, st_cert)
            print ("CA Certificate loaded succesfully from {0}".format(filename))
            print ("CA Certificate issued by {0}\n".format(ca_certificate.get_issuer()))
            return c,ca_certificate

    except IOError:
        print ("Certificate file couldn't be read. Exiting.")
        sys.exit()

# Print out the basic router hardening; Disable SSH, Enable Local Logging

def build_misc_hardening():
    print("!\nlogging buffered notifications")
    print("security authentication failure rate 3 log")
    print("logging userinfo\n!")

    print("no service tcp-small-servers")
    print("no service udp-small-servers")
    print("no service pad")
    print("no ip bootp server")
    print("no cdp run")
    print("no mop enabled")
    print("no ip redirects")
    print("no ip source-route")
    print("no ip unreachables")
    print("no ip proxy-arp")
    print("service tcp-keepalives-in")
    print("service tcp-keepalives-out")
    print("no ip http server\n!")


    print("crypto key generate rsa general-keys label ssh-keys modulus 2048")
    print("ip ssh rsa keypair-name ssh-keys")
    print("ip ssh time-out 60")
    print("ip ssh authentication-retries 3")
    print("ip ssh version 2")
    print("line vty 0 4\n!")
    print("transport input ssh\n!")

    print("service timestamps log datetime msec")
    print("service timestamps debug datetime msec\n!")

    print("login block-for 60 attempts 2 within 10")
    print("login delay 5\n")

# Print out the enable secret password

def build_enable_pass(password):
    print("enable secret {0}\n!".format(password))

# Program starts here!

print("\nWelcome to the Cisco IOS CPA Configuration Tool. ")
print("This tool can be used to generate a basic IPsec VPN configuration for Cisco IOS devices to meet the NCSC Foundation or End-State cryptographic profiles.\n")

if len(sys.argv) == 2:
    # Load the certificate (If supplied)
    c_obj, ca_cert = load_ca_cert(sys.argv[1])
    cert_supplied = True
elif len(sys.argv) == 1:
    print ("No CA certificate supplied. CA authentication will need to be performed manually\n")
    cert_supplied = False

# Grab and parse the hostname input. Error if the hostname is blank, contains spaces or ()

while True:
    hostname = input("Please enter the device hostname: ")
    if " " in hostname:
        print("Hostnames cannot contain spaces. Please try again.")
        continue
    elif '(' in hostname or ')' in hostname:
        print("Hostnames cannot contain illegal characters. Please try again.")
        continue
    elif hostname == "":
        print("Hostnames cannot be blank. Please try again.")
        continue
    else:
        break

# Grab IP Domain Name
domain_name = input("Please enter the domain name: ")

# Grab and parse enable secret password
while True:
    enable_pass = getpass.getpass("Please enter an enable secret password: ")
    if " " in enable_pass:
        print("Passwords cannot contain spaces. Please try again.")
        continue
    elif enable_pass == "":
        print("Passwords cannot be blank. Please try again.")
        continue
    else:
        break

# Determine the desired crypto profile and set the IKE version accordingly

while True:
    crypto_profile = input("Please enter the chosen crypto profile. Enter either (e)nd-state, (f)oundation or (i)nterim: ")
    if crypto_profile == "":
        continue
    elif crypto_profile[0] == "e":
        crypto_profile = "e"
        break
    elif crypto_profile[0] == "f":
        crypto_profile = "f"
        break
    elif crypto_profile[0] == "i":
        crypto_profile = "i"
        break
    else:
        print("The value you entered was not recognised, please try again.")
        continue

# Ask for certificate subject-name. Default to CN=hostname

cert_subject = input("Please enter the certificate subject-name. Example: cn=myRouter,ou=myDept,o=myCompany (Default: cn={0}.{1}): ".format(hostname,domain_name))
if cert_subject == "":
    cert_subject = "cn={0}.{1}".format(hostname,domain_name)

subject_name=[]
z = 0

# Split subject-name in to list and parse each section to make sure it is properly formatted. i.e. that it has a recognised DN designator
# (CN, OU, O, C, DC) What about unstructured name.

for x, y in enumerate(cert_subject):
    if y == ",":
        subject_name.append(cert_subject[:x])
        cert_subject.lstrip(str(subject_name[z]))
        print(subject_name[z])
        z += 1

# Grab and check the IP address for the tunnel interface

tunnel_IP = check_ip("Please enter the IPv4 address of the IPsec tunnel interface: ")

# Grab and validate the tunnel interface mask. Default to 255.255.255.0

while True:
    tunnel_mask = input("Please enter the mask for the IPsec tunnel interface (Default 255.255.255.0): ")
    if tunnel_mask == "":
        tunnel_mask = "255.255.255.0"
        break
    elif not is_valid_mask(tunnel_mask):
        print("Invalid mask. Please try again.")
        continue
    else:
        break

# Grab the tunnel source interface

while True:
    tunnel_source = input("Please enter the tunnel source interface. Example: GigabitEthernet 0/0 or fa0/2: ")
    tunnel_src_number, good = check_interface_num(tunnel_source)
    if "gi" in tunnel_source and good:
        tunnel_source_int = "GigabitEthernet"
        break
    elif "fa" in tunnel_source and good:
        tunnel_source_int = "FastEthernet"
        break
    elif "lo" in tunnel_source and good:
        tunnel_source_int = "Loopback"
    else:
        print("Unknown interface type or designation, please try again. Supported interface types are Loopback, FastEthernet or GigabitEthernet")
        continue

# Finally grab and validate the tunnel destinate IP address. Make sure it doesn't match the tunnel IP address

while True:

    tunnel_destination = check_ip("Please enter the tunnel destination IPv4 address: ")
    if tunnel_destination == tunnel_IP:
        print ("Invalid entry. Destination IP address cannot be the same as the tunnel IP address.")
        continue
    else:
        break

# That's everything we need. Now spit out the configuration which can then be copied and pasted in to the router.

print("\n\nPlease copy and paste the following configuration in to your router. Make sure you're in configuration mode:\n")

write_basics(hostname, domain_name)
generate_keys(crypto_profile)
build_trustpoint(hostname,crypto_profile,cert_subject)
build_enable_pass(enable_pass)

if crypto_profile == "f":
    ipsec_profile = "foundation_profile"
    build_foundation(ipsec_profile)
    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                           tunnel_src_number)
elif crypto_profile == "e":
    ipsec_profile = "end_state_ipsec_profile"
    build_endstate(ipsec_profile)
    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                           tunnel_src_number)
elif crypto_profile == "i":
    ipsec_profile = "interim_profile"
    build_interim(ipsec_profile)
    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                           tunnel_src_number)
build_misc_hardening()

if cert_supplied:
    authenticate_trustpoint(c_obj, ca_cert)

while True:

    save_config = input("Would you like to save the configuration to file? (Y)es or (N)o: ")
    if save_config == "y":
        #Ask for the file name and then write the file
        config_filename = input("Please enter the filename:")
        with open(config_filename, 'w') as f:
            with redirect_stdout(f):
                write_basics(hostname, domain_name)
                build_enable_pass(enable_pass)
                generate_keys(crypto_profile)
                build_trustpoint(hostname, crypto_profile, cert_subject)

                if crypto_profile == "f":
                    ipsec_profile = "foundation_profile"
                    build_foundation(ipsec_profile)
                    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                                           tunnel_src_number)
                    build_misc_hardening()
                elif crypto_profile == "e":
                    ipsec_profile = "end_state_ipsec_profile"
                    build_endstate(ipsec_profile)
                    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                                           tunnel_src_number)
                    build_misc_hardening()
                elif crypto_profile == "i":
                    ipsec_profile = "interim_profile"
                    build_interim(ipsec_profile)
                    build_tunnel_interface(ipsec_profile, tunnel_IP, tunnel_mask, tunnel_destination, tunnel_source_int,
                                           tunnel_src_number)
                    build_misc_hardening()
                if cert_supplied:
                    authenticate_trustpoint(c_obj, ca_cert)

        print_final(cert_supplied)

        break
    elif save_config == "n":

        print_final(cert_supplied)

        break
    else:
        print("Please enter either (Y)es or (N)o")
        continue
        # Incorrect input so re-ask the question




