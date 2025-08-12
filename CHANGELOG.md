# Changelog

## [2.0.0] - 2025-08-12
debian [13.0] samba [4.22.3-Debian] rsyslog [8.2504.0] chrony [4.6.1] ssh [10.0p2] rsync [3.4.1] cron [3.0pl1-197]

### Added
- new package : samba-ad-dc chrony ntpsec-ntpdate vim
- new environment variables : Y_RSYSLOGD_AS_SERVER, Y_RSYSLOGD_SERVER, Y_CHRONYD, Y_CHRONYD_ADJTIMEX, Y_CHRONYD_OPTION
- rsyslog configuration is added : able to work as server, or send log to remote server
- ntp configuration is added : able to work with samba

### Removed
- package : ntp ntpdate
- environment variable : Y_NTPD

### Changed
- minor typo changes in entrypoint.sh for uniformity

## [1.0.0] - 2025-07-28
debian [12.11] samba [4.17.12-Debian] rsyslog [8.2302.0] ntpd ntpsec [1.2.2] ssh [9.2] rsync [3.2.7] cron [3.0pl1-162]

### Added
- première : first release.
