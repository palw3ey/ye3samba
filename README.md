# ye3samba

Samba image build on debian. GNS3 ready

The ye3samba image automates the initial setup and configuration of a Samba server, which can function as a standalone server, a domain controller (DC), or a domain member.  
It handles provisioning, domain joining, share configuration, and integrates with various services : rsyslog, ntpd, sshd, rsyncd and crond.

* [Simple usage](#user-content-simple-usage)
* [Advanced usage](#user-content-advanced-usage)
* [Prerequisite](#user-content-prerequisite)
* [Registry](#user-content-registry)
* [GNS3](#user-content-gns3)
* [Compatibility](#user-content-compatibility)
* [Build](#user-content-build)
* [SAMBA Links](#user-content-samba-links)
* [Ports](#user-content-ports)
* [Environment Variables](#user-content-environment-variables)
* [Version](#user-content-version)
* [Changelog](#user-content-changelog)
* [ToDo](#user-content-todo)
* [License](#user-content-license)

## Simple usage

Create a standalone samba server to share files

```bash
# create the nas folder on your host
mkdir ~/nas

# create and start
podman run -dt --name="mynas" \
    -v ~/nas:/nas \
    -p 137:137/udp -p 138:138/udp -p 139:139/tcp -p 445:445/tcp \
    -e Y_SHARE_NAME="nas" -e Y_SHARE_PATH="/nas" -e Y_SHARE_CHMOD="777" \
    -e Y_SHARE_OPTION="writable = yes | read only = no | hide dot files = no | vfs objects = recycle" \
    registry.gitlab.com/palw3ey/ye3samba

# logs
podman logs -f mynas

# add user
podman exec -it mynas adduser caroline 
podman exec -it mynas smbpasswd -a caroline
```
## Advanced usage

To show the capabilities, we will create 1 network and 3 containers : 
- a network :<br> named mynet46, subnet ipv4=10.1.192.0/24 ipv6=fd00::a01:c000/120 
- an active directory domain controller :<br> fqdn=dc1.samba.lan ipv4=10.1.192.11 ipv6=fd00::a01:c00b
- another domain controller :<br> fqdn=dc2.samba.lan ipv4=10.1.192.12 ipv6=fd00::a01:c00c
- a member server with a share :<br> fqdn=nas1.samba.lan ipv4=10.1.192.13 ipv6=fd00::a01:c00d

### Network
```bash
podman network create --ipv6 --subnet=10.1.192.0/24 --subnet=fd00::a01:c000/120 mynet46
```

### Active directory domain controller
```bash
podman run -dt --name="dc1" --cap-add="NET_RAW,SYS_TIME"  \
    --network="mynet46" --ip="10.1.192.11" --ip6="fd00::a01:c00b" \
    -e Y_RESOLV_OPTION="search samba.lan | nameserver 10.1.192.11" \
    -e Y_HOSTS_ENTRY="127.0.0.1 localhost | 10.1.192.11  dc1.samba.lan dc1" \
    -e Y_SERVER_ROLE="dc" -e Y_PROVISION_REALM="samba.lan" -e Y_PROVISION_DOMAIN="samba" -e Y_PROVISION_ADMINPASS="My_Str0ng_Dc_Passw0rd" \
    -e Y_NETBIOS_NAME="dc1" -e Y_RFC2307="yes" \
    -e Y_IDMAP_LOWERBOUND="45534" -e Y_IDMAP_UPPERBOUND="65533" \
    -e Y_PAM_KRB_MINIMUM_UID="45534" -e Y_PAM_MKHOMEDIR="yes" \
    -e Y_GENERAL_OPTION="dns forwarder = 1.1.1.1 | vfs objects = dfs_samba4 acl_xattr xattr_tdb | apply group policies = yes" \
    -e Y_REVERSE_ZONE="192.1.10.in-addr.arpa" -e Y_REVERSE_ZONE_CREATE="yes" -e Y_REVERSE_SERVER="dc1.samba.lan" \
    -e Y_REVERSE_PTR_NAME="11" -e Y_REVERSE_PTR_DATA="dc1.samba.lan" \
    -e Y_NTPD="yes" -e Y_RSYNCD="yes" -e Y_RSYNCD_USER="samba-replication" -e Y_RSYNCD_PASSWORD="My_Str0ng_Rsync_Passw0rd" \
    registry.gitlab.com/palw3ey/ye3samba

podman logs -f dc1
```

### Add a user
```bash
podman exec -it dc1 samba-tool user add caroline My_Str0ng_User_Passw0rd
```

### GPO : Install admx
```bash
podman exec -it dc1 bash

wget "https://download.microsoft.com/download/9/5/b/95be347e-c49e-4ede-a205-467c85eb1674/Administrative%20Templates%20(.admx)%20for%20Windows%2011%20Sep%202024%20Update.msi"

mkdir extracted_msi 

msiextract --directory /extracted_msi  "Administrative Templates (.admx) for Windows 11 Sep 2024 Update.msi"

samba-tool gpo admxload --username=administrator --password="My_Str0ng_Dc_Passw0rd"
samba-tool gpo admxload --username=administrator --password="My_Str0ng_Dc_Passw0rd" --admx-dir="/extracted_msi/Program Files/Microsoft Group Policy/Windows 11 Sep 2024 Update (24H2)/PolicyDefinitions/"

ls -l /var/lib/samba/sysvol/samba.lan/Policies/PolicyDefinitions
```

### Add another domain controller
```bash
# with unidirectional SysVol replication via cron and rsync

podman run -dt --name="dc2" --cap-add="NET_RAW,SYS_TIME"  \
    --network="mynet46" --ip="10.1.192.12" --ip6="fd00::a01:c00c" \
    -e Y_RESOLV_OPTION="search samba.lan | nameserver 10.1.192.12" \
    -e Y_HOSTS_ENTRY="127.0.0.1 localhost | 10.1.192.12  dc2.samba.lan dc2" \
    -e Y_SERVER_ROLE="dc" -e Y_JOIN_DOMAIN="samba.lan" -e Y_JOIN_SERVER="10.1.192.11" -e Y_JOIN_USER="Administrator" -e Y_JOIN_PASSWORD="My_Str0ng_Dc_Passw0rd" \
    -e Y_NETBIOS_NAME="dc2" -e Y_RFC2307="yes" \
    -e Y_IDMAP_LOWERBOUND="45534" -e Y_IDMAP_UPPERBOUND="65533" \
    -e Y_PAM_KRB_MINIMUM_UID="45534" -e Y_PAM_MKHOMEDIR="yes" \
    -e Y_GENERAL_OPTION="dns forwarder = 1.1.1.1 | vfs objects = dfs_samba4 acl_xattr xattr_tdb | apply group policies = yes" \
    -e Y_REVERSE_ZONE="192.1.10.in-addr.arpa" -e Y_REVERSE_SERVER="dc1.samba.lan" \
    -e Y_REVERSE_PTR_NAME="12" -e Y_REVERSE_PTR_DATA="dc2.samba.lan" \
    -e Y_NTPD="yes" -e Y_RSYNCD="yes" -e Y_RSYNCD_USER="samba-replication" -e Y_RSYNCD_PASSWORD="My_Str0ng_Rsync_Passw0rd" \
    -e Y_RSYNCD_SYSVOL_UPON_JOIN="yes" -e Y_RSYNCD_SYSVOL_SERVER="10.1.192.11" -e Y_RSYNCD_SYSVOL_CRON="*/5 * * * *" \
    registry.gitlab.com/palw3ey/ye3samba

podman logs -f dc2
```

### Show DRS replication status
```bash
podman exec -it dc2 samba-tool drs showrepl -U administrator --password=My_Str0ng_Dc_Passw0rd
```

### Add a member server with a share
```bash
podman run -dt --name="nas1" --cap-add="NET_RAW"  \
    --network="mynet46" --ip="10.1.192.13" --ip6="fd00::a01:c00d" \
    -e Y_RESOLV_OPTION="search samba.lan | nameserver 10.1.192.11" \
    -e Y_HOSTS_ENTRY="127.0.0.1 localhost | 10.1.192.13  nas1.samba.lan nas1" \
    -e Y_SERVER_ROLE="member" -e Y_JOIN_DOMAIN="samba.lan" -e Y_JOIN_SERVER="10.1.192.11" -e Y_JOIN_USER="Administrator@SAMBA.LAN" -e Y_JOIN_PASSWORD="My_Str0ng_Dc_Passw0rd" \
    -e Y_NETBIOS_NAME="nas1" \
    -e Y_IDMAP_LOWERBOUND="15533" -e Y_IDMAP_UPPERBOUND="65533" \
    -e Y_PAM_KRB_MINIMUM_UID="15533" -e Y_PAM_MKHOMEDIR="yes" \
    -e Y_GENERAL_OPTION="template homedir = /home/%D/%U | template shell = /bin/sh | winbind use default domain = Yes | idmap config * : backend  = tdb | idmap config * : range = 15533-25533 | vfs objects =  acl_xattr xattr_tdb  preopen readahead recycle | idmap config samba: backend = rid | idmap config samba: range = 45534-65533 | winbind enum users = Yes | winbind enum groups = Yes" \
    -e Y_REVERSE_ZONE="192.1.10.in-addr.arpa" -e Y_REVERSE_SERVER="dc1.samba.lan" \
    -e Y_REVERSE_PTR_NAME="13" -e Y_REVERSE_PTR_DATA="nas1.samba.lan" \
    -e Y_SHARE_HOMES="yes" -e Y_SHARE_NAME="nas" -e Y_SHARE_CHMOD="777" -e Y_SHARE_PATH="/nas" -e Y_SHARE_OPTION="writable = yes | read only = no | hide dot files = no" -e Y_SHARE_SDDL="O:BAG:DUD:AI(A;OICI;0x1201bf;;;DU)(A;OICI;0x1301bf;;;DU)(A;OICIID;FA;;;DA)(A;OICIID;FA;;;SY)" \
    registry.gitlab.com/palw3ey/ye3samba

podman logs -f nas1
```

### Get the ACL of /nas folder
```bash
podman exec -it nas1 getfacl /nas
```

### Run tests
```bash
podman exec -it nas1 wbinfo --ping-dc

# show dns zone
podman exec -it nas1 samba-tool dns zonelist dc1 --username=administrator --password=My_Str0ng_Dc_Passw0rd

# test dns resolve : ldap, kerberos, internal, external
podman exec -it nas1 host -t SRV _ldap._tcp.samba.lan.
podman exec -it nas1 host -t SRV _kerberos._udp.samba.lan.
podman exec -it nas1 host -t A nas1.samba.lan.
podman exec -it nas1 host -t A doc.ubuntu-fr.org

# test dns reverse
podman exec -it nas1 host -t PTR 10.1.192.13

# test file server
podman exec -it nas1 smbclient -L localhost -N

# test winbind
podman exec -it nas1 getent passwd administrator
podman exec -it nas1 getent group "Domain Users"

# test kerberos 
podman exec -it nas1 kinit administrator
podman exec -it nas1 klist

# test acl and extended attributes user and security (failed in rootless container, require root)
podman exec -it nas1 bash -c "touch test.txt ; setfacl -m g:adm:rwx test.txt ;  getfacl test.txt"
podman exec -it nas1 bash -c "touch test.txt ; setfattr -n user.userName -v userValue test.txt ; getfattr -d test.txt"
podman exec -it nas1 bash -c "touch test.txt ; setfattr -n security.secName -v secValue test.txt ; getfattr -n security.secName -d test.txt"

# test gpo
podman exec -it nas1 samba-tool gpo listall --username=administrator --password="My_Str0ng_Dc_Passw0rd"
podman exec -it nas1 samba-tool gpo getlink "DC=samba,DC=lan" --username=administrator --password="My_Str0ng_Dc_Passw0rd"

# test ldap query
podman exec -it nas1 ldapsearch -x -H ldaps://dc1.samba.lan -o tls_reqcert=never -D "CN=Administrator,CN=Users,DC=samba,DC=lan" -w "My_Str0ng_Dc_Passw0rd" -b "DC=samba,DC=lan" "(&(objectCategory=person)(objectClass=user)(sAMAccountName=caroline))"

# show SDDL ACL
podman exec -it nas1 mkdir /nas/newdir
podman exec -it nas1 samba-tool ntacl get --as-sddl /nas/newdir

# verify port
podman exec -it nas1 netstat -tulnp
```

### Modify the samba configuration
```bash
podman exec -it nas1 nano /etc/samba/smb.conf

# test
podman exec -it nas1 testparm

# reload to apply
podman exec -it nas1 smbcontrol all reload-config

# log
podman exec -it nas1 tail -f /var/log/samba/log.smbd
```

### Port mapping to use
```bash
# for a DC server : 
-p 53:53/tcp -p 53:53/udp -p 88:88/tcp -p 88:88/udp -p 135:135/tcp -p 137:137/udp -p 138:138/udp -p 139:139/tcp -p 389:389/tcp -p 389:389/udp -p 445:445/tcp -p 464:464/tcp -p 464:464/udp -p 636:636/tcp -p 3268:3268/tcp -p 3269:3269/tcp -p 49152-65535:49152-65535/tcp -p 123:123/udp 

# for a share server : 
-p 137:137/udp -p 138:138/udp -p 139:139/tcp -p 445:445/tcp 
```

### Test DC from a Windows computer that is not part of the domain
```bash
# open cmd.exe in local administrator, type this line and hit Enter :
notepad C:\Windows\System32\drivers\etc\hosts

# append this line, and close the file :
10.1.192.11    samba.lan

# from the cmd, type this line and hit Enter, this will open "Active directory users and computer" :
runas /netonly /user:samba.lan\Administrator "mmc.exe \"%SystemRoot%\system32\dsa.msc\" /domain=samba.lan"

# RSAT is required
```

### Other Windows tips
```bash
# connect to share with letter S
net use S: \\samba.lan\nas My_Str0ng_User_Passw0rd /user:samba\caroline

# list connections
net use

# show SDDL ACL
icacls \\samba.lan\nas
powershell -c "(Get-Acl '\\samba.lan\nas').Sddl"

# remove connections
net use \\samba\nas /delete

# remove saved password 
rundll32.exe keymgr.dll, KRShowKeyMgr
control.exe /name Microsoft.CredentialManager
```

## Prerequisite

Some knowledge of Linux, containerization, and Samba.

### Install Podman
```bash
# e.g. on Ubuntu 24.04.2 LTS, with crun and pasta
sudo apt update; sudo apt install podman crun passt
```

### Or install Docker
```bash
# e.g. on Ubuntu 24.04.2 LTS
sudo apt update; sudo apt install docker.io

# configuration
sudo groupadd docker; sudo usermod -aG docker $USER; newgrp docker; sudo systemctl enable --now docker
```

## Registry

| Registry | Image name |
|---|---|
| Docker | docker.io/palw3ey/ye3samba |
| Github | ghcr.io/palw3ey/ye3samba |
| Gitlab | registry.gitlab.com/palw3ey/ye3samba |
| Redhat | quay.io/palw3ey/ye3samba |

## GNS3

To run through GNS3, download and import the appliance : [ye3samba.gns3a](https://gitlab.com/palw3ey/ye3samba/-/raw/main/ye3samba.gns3a)

### How to connect the docker container in the GNS3 topology ?

 - Drag and drop the device in the topology.  
 - Right click on the device and select "Edit config".  
 - If you want a static configuration, uncomment the lines just below `# Static config for eth0` or otherwise `# DHCP config for eth0` for a dhcp configuration.  
 - Click "Save".  
 - Add a link to connect the device to a switch or router.
 - Finally, right click on the device, select "Start".  

To see the output, right click "Console".  
To type commands, right click "Auxiliary console".  

## Compatibility

The public image was build to work on these CPU architectures :

- linux/386
- linux/amd64
- linux/arm/v6
- linux/arm/v7
- linux/arm64/v8
- linux/ppc64le
- linux/s390x

## Build

To customize and create your own image.

```bash
git clone https://gitlab.com/palw3ey/ye3samba.git
cd ye3samba

# Make all your modifications, then :
podman build --no-cache --network=host -t ye3samba-dev .
podman run -dt --name mysamba-dev ye3samba-dev

# Verify
podman logs -f mysamba-dev
podman exec -it mysamba-dev ps -ef
podman exec -it mysamba-dev bash
```

## SAMBA Links

[Wiki = https://wiki.samba.org/ ](https://wiki.samba.org/)

[Manual = https://www.samba.org/samba/docs/current/man-html/](https://www.samba.org/samba/docs/current/man-html/)

## Ports

These are the ports you may use and their descriptions, depending on the role and service you choose.

| Port(s) | Description |
|---|---|
| 53 (TCP/UDP) | DNS (Name resolution) |
| 88 (TCP/UDP) | Kerberos (For authentication) |
| 123 (UDP) | NTP (Network Time Protocol - important for Kerberos time sync) |
| 135 (TCP) | RPC Endpoint Mapper |
| 137 (UDP) | NetBIOS Name Service |
| 138 (UDP) | NetBIOS Datagram Service |
| 139 (TCP) | NetBIOS Session Service (SMB over NetBIOS) |
| 389 (TCP/UDP) | LDAP (Directory services) |
| 445 (TCP) | SMB over TCP (CIFS) |
| 464 (TCP/UDP) | Kerberos kpasswd (Password changes) |
| 636 (TCP) | LDAPS (Secure LDAP) |
| 873 (TCP) | RSYNC |
| 3268 (TCP) | Global Catalog (LDAP) |
| 3269 (TCP) | Global Catalog SSL (LDAPS) |
| 49152-65535 (TCP) | Range for various RPC services |

## Environment Variables

These are the environment variables and their descriptions.  

| Variables | Default | Description |
| :- |:- |:- |
|TZ | Europe/Paris | {IANA format} time zone,  |
|Y_LANGUAGE | fr_FR | {locale code} Language. The list is in the folder /i18n |
|Y_DEBUG | no | {yes/no} yes, to run entrypoint.sh with "set -x" instead of "set -e" |
|Y_INIT | yes | {yes/no} no, to skip all init and configuration |
|Y_RSYSLOGD | yes | {yes/no} yes, to start rsyslogd service |
|Y_CROND | yes | {yes/no} yes, to start crond service |
|Y_RSYNCD | no | {yes/no} yes, to start rsyncd service |
|Y_NTPD | no | {yes/no} yes, to start ntpd service |
|Y_SSHD | no | {yes/no} yes, to start sshd service |
|Y_SSMTP_ROOT | | value to set for "root=" in /etc/ssmtp/ssmtp.conf|
|Y_SSMTP_MAILHUB | | value to set for "mailhub=" in /etc/ssmtp/ssmtp.conf|
|Y_SSMTP_HOSTNAME | | value to set for "hostname=" in /etc/ssmtp/ssmtp.conf|
|Y_RSYNCD_HOSTS_ALLOW | | value to set for "hosts allow = " in /etc/rsyncd.conf|
|Y_RSYNCD_USER | | value to set for "auth users = " in /etc/rsyncd.conf. value saved in /etc/rsyncd.secrets|
|Y_RSYNCD_PASSWORD | | value saved in /etc/rsyncd.secrets|
|Y_RSYNCD_SYSVOL_SERVER | | {IP Address/Hostname} IP of the server containing the sysvol to pull|
|Y_RSYNCD_SYSVOL_CRON | | cron time expression used to pull the sysvol (unidirectional SysVol replication) <br> e.g. */5 * * * *|
|Y_RSYNCD_SYSVOL_UPON_JOIN | | {yes/no} yes, to run a rsync command (pull sysvol and idmap) upon joining the domain|
|Y_HOSTS_ENTRY | | entries to put in /etc/hosts <br> e.g. Y_HOSTS_ENTRY="127.0.0.1 localhost \| ::1 ip6-localhost ip6-loopback \| 10.1.192.11  dc1.samba.lan dc1"|
|Y_RESOLV_OPTION | | options to put in /etc/resolv.conf <br> e.g. Y_RESOLV_OPTION="search samba.lan \| nameserver 10.1.192.11"|
|Y_IDMAP_LOWERBOUND | | value to set for "lowerBound:" in /usr/share/samba/setup/idmap_init.ldif|
|Y_IDMAP_LOWERBOUND | | value to set for "upperBound:" in /usr/share/samba/setup/idmap_init.ldif|
|Y_NETBIOS_NAME | | value to set for "netbios name = " in /etc/samba/smb.conf|
|Y_SERVER_ROLE | | value to set for "server role = " in /etc/samba/smb.conf <br> e.g. use 'dc', 'member' or 'standalone' |
|Y_RFC2307 | | {yes/no} yes, to add a line in /etc/samba/smb.conf that enable rfc2307|
|Y_DNS_BACKEND | | value to set for "server role = " in /etc/samba/smb.conf|
|Y_LOG_LEVEL | | value to set for "server role = " in /etc/samba/smb.conf|
|Y_PROVISION_REALM | | value to set for "--realm=" in the "samba-tool domain provision" command|
|Y_PROVISION_DOMAIN | | value to set for "--domain=" in the "samba-tool domain provision" command|
|Y_PROVISION_ADMINPASS | | value to set for "--adminpass=" in the "samba-tool domain provision" command|
|Y_PROVISION_HOST_IP | | value to set for "--host-ip=" in the "samba-tool domain provision" command|
|Y_JOIN_DOMAIN | | domain to join|
|Y_JOIN_USER | | value to set for "--server=" in the "samba-tool domain join" command|
|Y_JOIN_SERVER | | value to set for "--username=" in the "samba-tool domain join" command|
|Y_JOIN_PASSWORD | | value to set for "--password=" in the "samba-tool domain join" command|
|Y_GENERAL_OPTION | | options to add in the [general] section of /etc/samba/smb.conf <br> e.g. Y_GENERAL_OPTION="dns forwarder = 1.1.1.1 \| vfs objects = dfs_samba4 acl_xattr xattr_tdb \| apply group policies = yes"|
|Y_REVERSE_SERVER | | {IP Address/Hostname} IP of the DNS server to add the zone or record |
|Y_REVERSE_ZONE | | reverse zone <br> e.g. Y_REVERSE_ZONE="192.1.10.in-addr.arpa"|
|Y_REVERSE_ZONE_CREATE | | {yes/no} yes, to create the zone|
|Y_REVERSE_PTR_NAME | | PTR nam to add <br> e.g. Y_REVERSE_PTR_NAME="11"|
|Y_REVERSE_PTR_DATA | | PTR data to add <br> e.g. Y_REVERSE_PTR_DATA="dc1.samba.lan"|
|Y_SHARE_NAME | | the new share name to add, will be the section name in /etc/samba/smb.conf|
|Y_SHARE_PATH | | value to set for "path = " in the [Y_SHARE_NAME] section of /etc/samba/smb.conf|
|Y_SHARE_CHMOD | | chmod to apply for the Y_SHARE_PATH path <br> e.g. Y_SHARE_CHMOD="777"|
|Y_SHARE_CHOWN | | chown to apply for the Y_SHARE_PATH path <br> e.g. Y_SHARE_CHOWN="root:root"|
|Y_SHARE_SDDL | | SDDL (ntacl) to apply for the Y_SHARE_PATH path <br> e.g. Y_SHARE_SDDL="O:DAG:DAD:(A;;FRFX;;;DU)(A;OICI;FA;;;DA)(A;OICI;FA;;;SY)"|
|Y_SHARE_OPTION | | options to add in the [Y_SHARE_NAME] section of /etc/samba/smb.conf <br> e.g. Y_SHARE_OPTION="writable = yes \| read only = no \| hide dot files = no"|
|Y_SHARE_HOMES | | {yes/no} yes, to add [homes] section in /etc/samba/smb.conf|
|Y_REALM_KDC | | value to set for "kdc =" in /etc/krb5.conf|
|Y_PAM_MKHOMEDIR | | {yes/no} yes, to add pam_mkhomedir.so for pam common-session and samba|
|Y_PAM_KRB_MINIMUM_UID | | value to set for "minimum_uid=" argument of pam_krb5.so lines in pam|
|Y_LOG_TO_STDOUT | no | {yes/no} yes, to show samba log in the terminal instead of the log file <br> e.g. podman logs -f dc1 |
|Y_ULIMIT_SOFT | | value for soft ulimit |
|Y_ULIMIT_HARD | | value for hard ulimit |

## Version

| Name | Version |
| :- |:- |
|ye3samba | 1.0.0 |
|samba | 4.17.12-Debian |
|debian | 12.11 |

## Changelog

### [1.0.0] - 2025-07-28
#### Added
- première : first release

## ToDo

Feel free to contribute or share your ideas for new features, you can contact me on github, gitlab or by email. I speak French, you can write to me in other languages ​​I will find ways to translate.

## License

GPLv3  
author: palw3ey  
maintainer: palw3ey  
email: palw3ey@gmail.com  
website: https://gitlab.com/palw3ey/ye3samba  
docker hub: https://hub.docker.com/r/palw3ey/ye3samba
