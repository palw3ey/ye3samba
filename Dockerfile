FROM debian:stable-slim

ARG Y_TITLE="ye3samba"
ARG Y_VERSION="1.0.0"
ARG Y_CREATED="2025-07-08T15:00:00-03:00"
ARG Y_REVISION="20250708"
ARG Y_EXTRA=""

LABEL org.opencontainers.image.title=$Y_TITLE \
      org.opencontainers.image.version=$Y_VERSION \
      org.opencontainers.image.created=$Y_CREATED \
      org.opencontainers.image.revision=$Y_REVISION \
      org.opencontainers.image.base.name="registry.gitlab.com/palw3ey/$Y_TITLE:$Y_VERSION" \
      org.opencontainers.image.licenses="GPLv3" \
      org.opencontainers.image.authors="palw3ey" \
      org.opencontainers.image.vendor="palw3ey" \
      org.opencontainers.image.maintainer="palw3ey" \
      org.opencontainers.image.email="palw3ey@gmail.com" \
      org.opencontainers.image.url="https://gitlab.com/palw3ey/$Y_TITLE" \
      org.opencontainers.image.documentation="https://gitlab.com/palw3ey/$Y_TITLE/blob/main/README.md" \
      org.opencontainers.image.source="https://gitlab.com/palw3ey/$Y_TITLE" \
      org.opencontainers.image.usage="docker run -dt registry.gitlab.com/palw3ey/$Y_TITLE:latest" \
      org.opencontainers.image.description="Samba server on Debian. GNS3 ready" \
      org.opencontainers.image.tip="The folders /etc/samba, /var/lib/samba and /var/log/samba are persistent" \
      org.opencontainers.image.premiere="20250708"

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    tini tzdata rsyslog ntp ntpdate openssh-server \
    samba samba-ad-provision samba-common-bin samba-dsdb-modules samba-vfs-modules smbclient python3-cryptography python3-setproctitle \
    krb5-user krb5-config libpam-krb5 \
    winbind libpam-winbind libnss-winbind \
    cron rsync ssmtp openssl ca-certificates nano procps dnsutils tdb-tools ldb-tools ldap-utils attr acl msitools \
    wget curl iputils-ping iproute2 net-tools traceroute tcpdump

    # --- Conditional packages --- 
RUN if [ -n "$Y_EXTRA" ]; then DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends $Y_EXTRA; fi

    # --- Post-installation configuration ---
RUN mkdir -p /run/sshd && chmod 0755 /run/sshd && chown root:root /run/sshd \
    && mv /etc/samba/smb.conf /etc/samba/smb.conf.orig \
    && apt-get clean \
    && apt autoremove --yes \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/log/* /var/cache/*

VOLUME ["/etc/samba", "/var/lib/samba", "/var/log/samba"]

ADD i18n/ /i18n/
ADD entrypoint.sh /
RUN chmod 770 /entrypoint.sh \
    && chown root:root /entrypoint.sh

ENV TZ="Europe/Paris" \
    Y_LANGUAGE="fr_FR" \
    Y_DEBUG="no" \
    Y_INIT="yes" \
    Y_RSYSLOGD="yes" \
    Y_CROND="yes" \
    Y_RSYNCD="no" \
    Y_NTPD="no" \
    Y_SSHD="no" \
    Y_SSMTP_ROOT= \
    Y_SSMTP_MAILHUB= \
    Y_SSMTP_HOSTNAME= \
    Y_RSYNCD_HOSTS_ALLOW= \
    Y_RSYNCD_USER= \
    Y_RSYNCD_PASSWORD= \
    Y_RSYNCD_SYSVOL_SERVER= \
    Y_RSYNCD_SYSVOL_CRON= \
    Y_RSYNCD_SYSVOL_UPON_JOIN= \
    Y_HOSTS_ENTRY= \
    Y_RESOLV_OPTION= \
    Y_IDMAP_LOWERBOUND= \
    Y_IDMAP_UPPERBOUND= \
    Y_NETBIOS_NAME= \
    Y_SERVER_ROLE= \
    Y_RFC2307= \
    Y_DNS_BACKEND= \
    Y_LOG_LEVEL= \
    Y_PROVISION_REALM= \
    Y_PROVISION_DOMAIN= \
    Y_PROVISION_ADMINPASS= \
    Y_PROVISION_HOST_IP= \
    Y_JOIN_DOMAIN= \
    Y_JOIN_USER= \
    Y_JOIN_SERVER= \
    Y_JOIN_PASSWORD= \
    Y_GENERAL_OPTION= \
    Y_REVERSE_SERVER= \
    Y_REVERSE_ZONE= \
    Y_REVERSE_ZONE_CREATE= \
    Y_REVERSE_PTR_NAME= \
    Y_REVERSE_PTR_DATA= \
    Y_SHARE_NAME= \
    Y_SHARE_PATH= \
    Y_SHARE_CHMOD= \
    Y_SHARE_CHOWN= \
    Y_SHARE_SDDL= \
    Y_SHARE_OPTION= \
    Y_SHARE_HOMES= \
    Y_REALM_KDC= \
    Y_PAM_MKHOMEDIR= \
    Y_PAM_KRB_MINIMUM_UID= \
    Y_LOG_TO_STDOUT="no" \
    Y_ULIMIT_SOFT= \
    Y_ULIMIT_HARD=

# Expose all necessary ports for Samba Active Directory Domain Controller (AD DC) functionality.
#
# Key Ports:
#   - 53 (TCP/UDP): DNS (Name resolution)
#   - 88 (TCP/UDP): Kerberos (For authentication)
#   - 135 (TCP): RPC Endpoint Mapper
#   - 137 (UDP): NetBIOS Name Service
#   - 138 (UDP): NetBIOS Datagram Service
#   - 139 (TCP): NetBIOS Session Service (SMB over NetBIOS)
#   - 389 (TCP/UDP): LDAP (Directory services)
#   - 445 (TCP): SMB over TCP (CIFS)
#   - 464 (TCP/UDP): Kerberos kpasswd (Password changes)
#   - 636 (TCP): LDAPS (Secure LDAP)
#   - 3268 (TCP): Global Catalog (LDAP)
#   - 3269 (TCP): Global Catalog SSL (LDAPS)
#
# Dynamic RPC Ports:
#   - 49152-65535 (TCP): Range for various RPC services.
#
# Optional:
#   - 123 (UDP): NTP (Network Time Protocol - important for Kerberos time sync)
#   - 873 (TCP): RSYNC
# EXPOSE 53/tcp 53/udp 88/tcp 88/udp 135/tcp 137/udp 138/udp 139/tcp 389/tcp 389/udp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp 3269/tcp 49152-65535/tcp 123/udp 873/tcp

ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/entrypoint.sh"]
