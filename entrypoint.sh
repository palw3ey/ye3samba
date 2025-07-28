#!/bin/bash
#
# Entrypoint script for gitlab.com/palw3ey/ye3samba
#
# Description:
#   This script serves as the primary entrypoint for the 'ye3samba' container.
#
# License: GPLv3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
# Author: palw3ey@gmail.com
# Date: 2025-07-28
# Version: 1.0.0
#


#
# ============ [ global variable ] ============
#


# path
v_smb_conf="/etc/samba/smb.conf"
v_idmap_init="/usr/share/samba/setup/idmap_init.ldif"
v_sysvol="/var/lib/samba/sysvol/"
v_idmap="/var/lib/samba/private/idmap.ldb"
v_krb_conf="/var/lib/samba/private/krb5.conf"
v_krb_conf_etc="/etc/krb5.conf"
v_pam_session="/etc/pam.d/common-session"
v_pam_common="/etc/pam.d/common-"
v_pam_samba="/etc/pam.d/samba"
v_ssmtp_conf="/etc/ssmtp/ssmtp.conf"
v_rsyncd_conf="/etc/rsyncd.conf"
v_rsyncd_secrets="/etc/rsyncd.secrets"
v_rsyncd_sysvol_secret="/etc/rsync-sysvol.secret"
v_rsync_idmap_output="/var/log/rsync_idmap_output.log"
v_rsync_sysvol_output="/var/log/rsync_sysvol_output.log"
v_log_auth="/var/log/auth.log"
v_log_mail="/var/log/mail.log"
v_crond_root_cache="/root/.cache"
v_resolv_conf="/etc/resolv.conf"
v_hosts_conf="/etc/hosts"
v_i18n="/i18n/"

# bin
v_smbd_bin="/usr/sbin/smbd"
v_smbd_pid="/var/run/samba/smbd.pid"
v_nmbd_bin="/usr/sbin/nmbd"
v_nmbd_pid="/var/run/samba/nmbd.pid"
v_winbindd_bin="/usr/sbin/winbindd"
v_winbindd_pid="/var/run/samba/winbindd.pid"
v_samba_bin="/usr/sbin/samba"
v_samba_pid="/var/run/samba/samba.pid"
v_samba_tool_bin="/usr/bin/samba-tool"
v_tdbbackup_bin="/usr/bin/tdbbackup"
v_pam_auth_update_bin="/usr/sbin/pam-auth-update"
v_rsyslogd_bin="/usr/sbin/rsyslogd"
v_rsyslogd_pid="/var/run/rsyslogd.pid"
v_ntpd_bin="/usr/sbin/ntpd"
v_ntpd_pid="/var/run/ntpd.pid"
v_crond_bin="/usr/sbin/cron"
v_crond_pid="/var/run/crond.pid"
v_sshd_bin="/usr/sbin/sshd"
v_sshd_pid="/var/run/sshd.pid"
v_rsyncd_bin="/usr/bin/rsync"
v_rsyncd_pid="/var/run/rsyncd.pid"

# other
v_default_language="fr_FR"
v_first_run="no"
v_is_domain_controller="no"
v_ansi_red="\033[0;31m"
v_ansi_green="\033[0;32m"
v_ansi_yellow="\033[0;33m"
v_ansi_blue="\033[0;34m"
v_ansi_magenta="\033[0;35m"
v_ansi_bold="\033[1m"
v_ansi_underline="\033[4m"
v_ansi_nc="\033[0m" 

# save the original Internal Field Separator
OLDIFS=$IFS


#
# ============ [ function ] ============
#


# Function to display a given message
# Arguments:
#   $1: message - The string message to be displayed.
#   $2: style   - (Optional) An ANSI escape code for styling the message
f_message(){
    local message="$1"
    local style="$2"

    if [ -n "$message" ]; then
        if [ -n "$style" ]; then
            echo -e "${style}${message}${v_ansi_nc}"
        else
            echo -e "${v_ansi_underline}${message}${v_ansi_nc}"
        fi
    fi 
}


# Function to keep running and exit the entire script
f_stay_and_exit(){

    f_message ":: $i_ready ::" "$v_ansi_green"
    tail -f /dev/null
    exit 0

}


# Function to append configuration entries to a file
# Arguments:
#   $1: Entries as a string, separated by '|' (e.g., "entry1 | entry2 | entry3")
#   $2: Path to the configuration file
#   $3: (Optional) Prefix for each entry
#   $4: (Optional) Suffix for each entry
f_append_config() {
    local input_string="$1"
    local conf_file="$2"
    local prefix="$3"
    local suffix="$4" 
    local processed_entries=""

    # Process each entries
    # a) Trim leading/trailing spaces from the whole input_string string
    # b) Replace " <spaces> | <spaces> " with a single newline.
    processed_entries=$(echo "$input_string" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/[[:space:]]*|[[:space:]]*/\n/g')

    echo "$processed_entries" | while IFS= read -r item_raw; do

        # Trim leading/trailing spaces from the current entries
        _trimmed_item=$(echo "$item_raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Only process non-empty items (in case sed created empty lines from double delimiters etc.)
        if [ -n "$_trimmed_item" ]; then
            echo "${prefix}${_trimmed_item}${suffix}" >> "$conf_file"
        fi

    done

    IFS=$OLDIFS
}


# Function to rewrite configuration file
# Arguments:
#   $1: Entries as a string, separated by '|'
#   $2: Path to the configuration file
f_rewrite_conf() {

    local input_string="$1"
    local conf_file="$2"

    if [ -n "$Y_HOSTS_ENTRY" ]; then

        f_message "$i_modifying : $conf_file"

        # backup
        [ ! -f "${conf_file}.bak" ] && cp "$conf_file" "${conf_file}.bak"

        # clear
        truncate -s 0 "$conf_file"

        # modify
        f_append_config "$input_string" "$conf_file"

    fi

}


#
# ============ [ some init ] ============
#


# if you don't want to go further in this entrypoint script,
# configuration process wont begin and processes wont be started
if [ "$Y_INIT" != "yes" ]; then
    f_stay_and_exit
fi

# add error handling
if [ "$Y_DEBUG" = "yes" ]; then set -x ; else set -e ; fi

# is server role dc
server_role=$(echo "$Y_SERVER_ROLE" | tr '[:upper:]' '[:lower:]')
if [ "$server_role" = "dc" ] || [ "$server_role" = "domain controller" ]; then
    v_is_domain_controller="yes"
fi

# change timezone
cp /usr/share/zoneinfo/$TZ /etc/localtime || true
echo "$TZ" > /etc/timezone || true

# show date
echo [$(date "+%Y-%m-%dT%H:%M:%S%z")]

# load default language
if [ -f "$v_i18n/$v_default_language.sh" ]; then
	source $v_i18n/$v_default_language.sh
fi

# override with choosen language
if [ "$Y_LANGUAGE" != "$v_default_language" ] && [ -f "$v_i18n/$Y_LANGUAGE.sh" ]; then
    source $v_i18n/$Y_LANGUAGE.sh
fi
f_message "i18n : $Y_LANGUAGE"

# hosts
[ -n "$Y_HOSTS_ENTRY" ] && f_rewrite_conf "$Y_HOSTS_ENTRY" "$v_hosts_conf"


#
# ============ [ configuration ] ============
#


# if it is the first run, then show the header and start configuration
if [ ! -f "$v_smb_conf" ]; then

# header
cat <<'EOF'

Bienvenue !
             _____                     _           
  _   _  ___|___ / ___  __ _ _ __ ___ | |__   __ _ 
 | | | |/ _ \ |_ \/ __|/ _` | '_ ` _ \| '_ \ / _` |
 | |_| |  __/___) \__ \ (_| | | | | | | |_) | (_| |
  \__, |\___|____/|___/\__,_|_| |_| |_|_.__/ \__,_|
  |___/                                            
                                    palw3ey / GPLv3

EOF

    v_first_run="yes"

    # initialize positional parameters to empty
    set --

    # idmap bound
    if [ -n "$Y_IDMAP_LOWERBOUND" ] && [ -n "$Y_IDMAP_UPPERBOUND" ]; then
        sed -i "s|lowerBound: 3000000|lowerBound: $Y_IDMAP_LOWERBOUND|" "$v_idmap_init"
        sed -i "s|upperBound: 4000000|upperBound: $Y_IDMAP_UPPERBOUND|" "$v_idmap_init"
    fi

    # provision
    if [ -n "$Y_PROVISION_REALM" ] && [ -n "$Y_PROVISION_DOMAIN" ] && [ -n "$Y_PROVISION_ADMINPASS" ]; then

        f_message "$i_start_provisioning : $Y_PROVISION_REALM"

        set -- "$@" "provision"
        set -- "$@" "--server-role=$server_role"
        set -- "$@" "--realm=${Y_PROVISION_REALM}"
        set -- "$@" "--domain=${Y_PROVISION_DOMAIN}"
        set -- "$@" "--adminpass=${Y_PROVISION_ADMINPASS}"
        [ -n "$Y_NETBIOS_NAME" ] && set -- "$@" "--host-name=${Y_NETBIOS_NAME}"
        [ -n "$Y_PROVISION_HOST_IP" ] && set -- "$@" "--host-ip=${Y_PROVISION_HOST_IP}"

        # rfc2307
        [ "$Y_RFC2307" = "yes" ] && _rfc2307="--use-rfc2307"

        _samba_tool="yes"

    # join
    elif [ -n "$Y_JOIN_DOMAIN" ] && [ -n "$Y_JOIN_SERVER" ] && [ -n "$Y_JOIN_USER" ]  && [ -n "$Y_JOIN_PASSWORD" ]; then

        f_message "$i_start_joining : $Y_JOIN_DOMAIN" 

        set -- "$@" "join"
        set -- "$@" "$Y_JOIN_DOMAIN"
        set -- "$@" "$server_role"
        set -- "$@" "--server=$Y_JOIN_SERVER"
        set -- "$@" "--username=$Y_JOIN_USER"
        set -- "$@" "--password=$Y_JOIN_PASSWORD"

        # rfc2307
        [ "$Y_RFC2307" = "yes" ] && _rfc2307="--option=idmap_ldb:use rfc2307 = yes"

        # set nameserver to the server to join
        # Y_RESOLV_OPTION is not required here, but prevent you to modify resolv if you dont provived a resolv config.
        # e.g. Y_RESOLV_OPTION="nameserver NEW.CONTAINER.IP.ADDRESS", this will resist any reboot.
        if [ -n "$Y_RESOLV_OPTION" ]; then

            f_rewrite_conf "nameserver $Y_JOIN_SERVER" "$v_resolv_conf"

        fi

        _samba_tool="yes"

    # something else
    else

        f_message "$i_writting : $v_smb_conf" 

        echo -e "[global]" > "$v_smb_conf"
        [ -n "$Y_NETBIOS_NAME" ] && echo -e "        netbios name = $Y_NETBIOS_NAME" >> "$v_smb_conf"
        [ -n "$Y_SERVER_ROLE" ] && echo -e "        server role = $Y_SERVER_ROLE" >> "$v_smb_conf"
        [ -n "$Y_LOG_LEVEL" ] && echo -e "        log level = $Y_LOG_LEVEL" >> "$v_smb_conf"
        [ "$Y_RFC2307" = "yes" ] && echo -e "        idmap config * : schema_mode = rfc2307 " >> "$v_smb_conf"

        f_append_config "$Y_GENERAL_OPTION" "$v_smb_conf" "        "
		
        f_message "$i_disable_auth_module : krb5" 

        DEBIAN_FRONTEND=noninteractive "$v_pam_auth_update_bin" --remove krb5 --force

    fi

    if [ "$_samba_tool" = "yes" ]; then

        # append arguments
        [ -n "$Y_NETBIOS_NAME" ] && set -- "$@" "--option=netbios name = ${Y_NETBIOS_NAME}"
        [ -n "$Y_DNS_BACKEND" ] && set -- "$@" "--dns-backend=$Y_DNS_BACKEND"
        [ -n "$Y_LOG_LEVEL" ] && set -- "$@" "--debuglevel=$Y_LOG_LEVEL"
        [ -n "$_rfc2307" ] && set -- "$@" "$_rfc2307"

        _general_option=$(echo "$Y_GENERAL_OPTION" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/[[:space:]]*|[[:space:]]*/\n/g')
        _new_args_to_add=""
        _option_args_from_loop=$(echo "$_general_option" | while IFS= read -r item_raw; do
            _trimmed_item=$(echo "$item_raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -n "$_trimmed_item" ]; then
                echo "--option=$_trimmed_item"
            fi
        done)
        _new_args_to_add=$(printf "%b" "${_new_args_to_add}${_option_args_from_loop}")
        _new_args_to_add=$(echo -n "$_new_args_to_add" | sed '$s/\n$//')

IFS='
'
        set -- "$@" $_new_args_to_add
        IFS=$OLDIFS

        # run samba-tool with the arguments
        samba-tool domain "$@"

        # setup krb
        _base_domain="${Y_PROVISION_REALM:-$Y_JOIN_DOMAIN}"
        _upper_y_realm=$(echo "$_base_domain" | tr '[:lower:]' '[:upper:]')
        _lower_y_realm=$(echo "$_base_domain" | tr '[:upper:]' '[:lower:]')

        if [ -f "$v_krb_conf" ]; then 

            # copy krb conf
            cp -f "$v_krb_conf" "$v_krb_conf_etc"

        else

            # create krb conf
cat > "$v_krb_conf_etc"<<EOF
[libdefaults]
        default_realm = $_upper_y_realm
        dns_lookup_realm = false
        dns_lookup_kdc = true

[realms]
$_upper_y_realm = {
        default_domain = $_lower_y_realm
}

[domain_realm]
        .$_lower_y_realm = $_upper_y_realm
        $_lower_y_realm = $_upper_y_realm
EOF

        fi

        # update krb conf
        if [ -n "$Y_REALM_KDC" ]; then
            sed -i "/default_domain = $_lower_y_realm/a \ \ \ \ \ \ \ \ kdc = $Y_REALM_KDC" "$v_krb_conf_etc"
        fi

        # update krb pam
        if [ -n "$Y_PAM_KRB_MINIMUM_UID" ] && [ -f "$v_pam_samba" ]; then
            sed -i "s/pam_krb5.so minimum_uid=1000\b/pam_krb5.so minimum_uid=$Y_PAM_KRB_MINIMUM_UID/g" "$v_pam_common"*
        fi

    fi 

    # configure share
    if [ -n "$Y_SHARE_NAME" ]; then

        f_message "$i_configuring_share : $Y_SHARE_NAME" 

        # create section
        echo -e "\n[$Y_SHARE_NAME]" >> "$v_smb_conf"

        if [ -n "$Y_SHARE_PATH" ]; then 

            # create share folder
            mkdir -p "$Y_SHARE_PATH" || true

            # posix permission
            if [ -n "$Y_SHARE_CHMOD" ]; then
                chmod "$Y_SHARE_CHMOD" "$Y_SHARE_PATH" || true
            fi

            # posix ownership
            if [ -n "$Y_SHARE_CHOWN" ]; then
                chown "$Y_SHARE_CHOWN" "$Y_SHARE_PATH" || true
            fi

            echo -e "        path = $Y_SHARE_PATH" >> "$v_smb_conf"

        fi

        # append all other share option
        f_append_config "$Y_SHARE_OPTION" "$v_smb_conf" "        "

    fi

    # configure share homes
    if [ "$Y_SHARE_HOMES" = "yes" ]; then

        f_message "$i_configuring_share : homes"

cat >> "$v_smb_conf"<<EOF

[homes]
        comment = Home Directories
        browseable = no
        read only = no
        create mask = 0700
        directory mask = 0700
        valid users = %S
        path = %H 
EOF

    fi

    # configure pam mkhomedir 
    if [ "$Y_PAM_MKHOMEDIR" = "yes" ]; then

        f_message "$i_configuring : pam mkhomedir"

        pam_mkhomedir_line="session required pam_mkhomedir.so skel=/etc/skel umask=0077"

        if [ -f "$v_pam_session" ] && ! grep -qxF "$pam_mkhomedir_line" "$v_pam_session"; then
            sed -i '$a\'"$pam_mkhomedir_line" "$v_pam_session"
        fi
        if [ -f "$v_pam_samba" ] && ! grep -qxF "$pam_mkhomedir_line" "$v_pam_samba"; then
            sed -i '$a\'"$pam_mkhomedir_line" "$v_pam_samba"
        fi

    fi

    # configure ssmtp, to send mail
    f_message "$i_configuring : ssmtp"

    if [ -n "$Y_SSMTP_ROOT" ]; then
        sed -i "/^root/c root=$Y_SSMTP_ROOT" "$v_ssmtp_conf"
    fi

    if [ -n "$Y_SSMTP_MAILHUB" ]; then
        sed -i "/^mailhub/c mailhub=$Y_SSMTP_MAILHUB" "$v_ssmtp_conf"
    fi

    if [ -n "$Y_SSMTP_HOSTNAME" ]; then
        sed -i "/^hostname/c hostname=$Y_SSMTP_HOSTNAME" "$v_ssmtp_conf"
    fi

    # configure rsyncd
    if [ "$Y_RSYNCD" = "yes" ]; then

        f_message "$i_configuring : rsyncd"

        if [ -n "$Y_RSYNCD_USER" ] && [ -n "$Y_RSYNCD_PASSWORD" ] ; then
            echo "$Y_RSYNCD_USER:$Y_RSYNCD_PASSWORD" > "$v_rsyncd_secrets"
            chmod 600 "$v_rsyncd_secrets"
            _rsync_secrets_file="secrets file = $v_rsyncd_secrets"
        fi

        if [ -n "$Y_RSYNCD_USER" ]; then
            _rsync_rsyncd_user="auth users = $Y_RSYNCD_USER"
        fi

        if [ -n "$Y_RSYNCD_HOSTS_ALLOW" ]; then
            _rsync_hosts_allow="hosts allow = $Y_RSYNCD_HOSTS_ALLOW"
        fi

cat > "$v_rsyncd_conf"<<EOF
uid = root
gid = root
use chroot = no
pid file = $v_rsyncd_pid
$_rsync_secrets_file

[SysVol]
path = $v_sysvol
comment = Samba Sysvol Share
read only = yes
$_rsync_rsyncd_user
$_rsync_hosts_allow
EOF

    fi

    # configure cron
    f_message "$i_configuring : cron"
    _current_crontab_content=$(crontab -l -u root 2>/dev/null || true)
    (
        echo "MAILTO='root'"
        echo "MAILFROM='root@localhost'"
        echo "$_current_crontab_content"
    ) > _temp_crontab_new

    if [ ! -d "$v_crond_root_cache" ]; then
        mkdir -p "$v_crond_root_cache"
        chown root:root "$v_crond_root_cache"
        chmod 700 "$v_crond_root_cache"
    fi

    crontab -u root _temp_crontab_new || true
    rm _temp_crontab_new

    # configure rsync sysvol cron
    if  [ "$v_is_domain_controller" = "yes" ] && [ -n "$Y_RSYNCD_SYSVOL_CRON" ] && [ -n "$Y_RSYNCD_SYSVOL_SERVER" ]; then

        if [ -n "$Y_RSYNCD_USER" ]; then
            _cron_sysvol_user="${Y_RSYNCD_USER}@"
        fi

        if [ -n "$Y_RSYNCD_PASSWORD" ]; then
            echo "$Y_RSYNCD_PASSWORD" > "$v_rsyncd_sysvol_secret"
            chmod 600 "$v_rsyncd_sysvol_secret"
            _cron_password_file="--password-file=$v_rsyncd_sysvol_secret"
        fi

        _rsync_sysvol_command="$v_rsyncd_bin -XAavz --delete-after $_cron_password_file rsync://${_cron_sysvol_user}${Y_RSYNCD_SYSVOL_SERVER}/SysVol/ $v_sysvol"

        # sync idmap and sysvol after domain join
        if [ "$Y_RSYNCD_SYSVOL_UPON_JOIN" = "yes" ]; then

            f_message "$i_pulling_idmap_ldb_from : $Y_RSYNCD_SYSVOL_SERVER"
            _rsync_idmap_command="$v_rsyncd_bin -XAavz --delete-after $_cron_password_file rsync://${_cron_sysvol_user}${Y_RSYNCD_SYSVOL_SERVER}/SysVol/idmap.ldb $v_idmap"
            $_rsync_idmap_command > "$v_rsync_idmap_output" || true
            tail -n 2 "$v_rsync_idmap_output"

            f_message "$i_running : net cache flush"
            net cache flush || true

            f_message "$i_pulling_sysvol_from : $Y_RSYNCD_SYSVOL_SERVER"
            $_rsync_sysvol_command > "$v_rsync_sysvol_output" || true
            tail -n 2 "$v_rsync_sysvol_output"

            f_message "$i_running : samba-tool ntacl sysvolreset"
            samba-tool ntacl sysvolreset || true

        fi

        f_message "$i_configuring : cron rsync sysvol"

        # add cron job for sysvol
        echo "$(crontab -l -u root 2>/dev/null)" > temp_crontab
        echo "$Y_RSYNCD_SYSVOL_CRON $_rsync_sysvol_command > /dev/null 2>&1" >> temp_crontab
        crontab -u root temp_crontab || true
        rm temp_crontab

    fi

    f_message ":: $i_finished_initial_configuration ::" "$v_ansi_magenta"

fi


#
# ============ [ pre start ] ============
#


# adjust open file descritors limit

if [ -n "$Y_ULIMIT_SOFT" ]; then

    f_message "$i_adjusting : ulimit soft"

    ulimit -S -n "$Y_ULIMIT_SOFT"

fi

if [ -n "$Y_ULIMIT_HARD" ]; then

    f_message "$i_adjusting : ulimit hard"

    ulimit -H -n "$Y_ULIMIT_HARD"

fi

# modify resolv
[ -n "$Y_RESOLV_OPTION" ] && f_rewrite_conf "$Y_RESOLV_OPTION" "$v_resolv_conf"


#
# ============ [ start ] ============
#


# run rsyslogd
if [ "$Y_RSYSLOGD" = "yes" ]; then

    f_message "$i_starting : rsyslogd"

    touch "$v_log_auth" "$v_log_mail" || true
    chown root:adm "$v_log_auth" "$v_log_mail" || true
    chmod 640 "$v_log_auth" "$v_log_mail" || true

    [ -f "$v_rsyslogd_pid" ] && rm -f "$v_rsyslogd_pid"
    "$v_rsyslogd_bin" > /dev/null 2>&1 &
fi

# run ntpd
if [ "$Y_NTPD" = "yes" ]; then
    f_message "$i_starting : ntpd"
    [ -f "$v_ntpd_pid" ] && rm -f "$v_ntpd_pid"
    "$v_ntpd_bin" -p "$v_ntpd_pid" > /dev/null 2>&1 &
fi

# run sshd
if [ "$Y_SSHD" = "yes" ]; then
    f_message "$i_starting : sshd"
    [ -f "$v_sshd_pid" ] && rm -f "$v_sshd_pid"
    "$v_sshd_bin" > /dev/null 2>&1 &
fi

# run rsyncd
if [ "$Y_RSYNCD" = "yes" ]; then

    f_message "$i_starting : rsyncd"

    [ -f "$v_rsyncd_pid" ] && rm -f "$v_rsyncd_pid"
    "$v_rsyncd_bin" --daemon > /dev/null 2>&1 &

fi

# run crond
if [ "$Y_CROND" = "yes" ]; then
    f_message "$i_starting : crond"
    [ -f "$v_crond_pid" ] && rm -f "$v_crond_pid"
    "$v_crond_bin" -l 0 > /dev/null 2>&1 &
fi

f_message "$i_starting : samba"

# clean previous samba start
[ -f "$v_samba_pid" ] && rm -f "$v_samba_pid"
[ -f "$v_smbd_pid" ] && rm -f "$v_smbd_pid"
[ -f "$v_nmbd_pid" ] && rm -f "$v_nmbd_pid"
[ -f "$v_winbindd_pid" ] && rm -f "$v_winbindd_pid"

if [ "$v_is_domain_controller" = "yes" ]; then

    # start samba
    if [ "$Y_LOG_TO_STDOUT" = "yes" ]; then
        "$v_samba_bin" --interactive &
    else
        "$v_samba_bin" > /dev/null 2>&1 &
    fi

else

    # start smbd, nmbd and winbindd
    if [ "$Y_LOG_TO_STDOUT" = "yes" ]; then
        "$v_smbd_bin" -F --no-process-group --debug-stdout &
        "$v_nmbd_bin" -F --no-process-group --debug-stdout &
        "$v_winbindd_bin" -F --no-process-group --debug-stdout &
    else 
        "$v_smbd_bin" > /dev/null 2>&1 &
        "$v_nmbd_bin" > /dev/null 2>&1 &
        "$v_winbindd_bin" > /dev/null 2>&1 &
    fi

fi


#
# ============ [ post start ] ============
#


if  [ "$v_first_run" = "yes" ]; then

    : # add here all your post start logic that will run once only
   
    _admin_user="${Y_JOIN_USER:-administrator}"
    _admin_password="${Y_JOIN_PASSWORD:-$Y_PROVISION_ADMINPASS}"

    if  [ -n "$Y_REVERSE_SERVER" ] && [ -n "$Y_REVERSE_ZONE" ] && [ -n "$_admin_password" ]; then

        # just wait a little for samba service to be ready
        sleep 1

        _timeout=5
        _interval=1

        # add reverse zone
        if [ "$Y_REVERSE_ZONE_CREATE" = "yes" ]; then

            f_message "$i_creating_zone"

            _elapsed=0

            while true; do

                _command_output=$("$v_samba_tool_bin" dns zonecreate "$Y_REVERSE_SERVER" "$Y_REVERSE_ZONE" --username="$_admin_user" --password="$_admin_password" 2>&1 || true)
                _command_exit_code=$?

                echo "$_command_output"
                [ $_command_exit_code -eq 0 ] && break
                echo "$_command_output" | grep -q "WERR_DNS_ERROR_ZONE_ALREADY_EXISTS" && break

                if [ "$_elapsed" -ge "$_timeout" ]; then
                    f_message "$i_aborted_no_success_within : ${_timeout} $i_seconds." "$v_ansi_red"
                    break
                fi

                f_message "$i_waiting (${_elapsed}s/${_timeout}s)"
                sleep "$_interval"
                _elapsed=$((_elapsed + _interval))

            done

        fi

        # add ptr record
        if  [ -n "$Y_REVERSE_PTR_NAME" ] && [ -n "$Y_REVERSE_PTR_DATA" ] ; then

            f_message "$i_adding_record : PTR"

            _elapsed=0

            while true; do

                _command_output=$("$v_samba_tool_bin" dns add "$Y_REVERSE_SERVER" "$Y_REVERSE_ZONE" "$Y_REVERSE_PTR_NAME" PTR "$Y_REVERSE_PTR_DATA" --username="$_admin_user" --password="$_admin_password" 2>&1 || true)
                _command_exit_code=$?

                echo "$_command_output"
                [ $_command_exit_code -eq 0 ] && break
                echo "$_command_output" | grep -q "Record already exists" && break

                if [ "$_elapsed" -ge "$_timeout" ]; then
                    f_message "$i_aborted_no_success_within ${_timeout} $i_seconds." "$v_ansi_red"
                    break
                fi

                f_message "$i_waiting (${_elapsed}s/${_timeout}s)"
                sleep "$_interval"
                _elapsed=$((_elapsed + _interval))

            done

        fi

    fi

    # apply nt acl in sddl format
    if  [ -n "$Y_SHARE_NAME" ] && \
        [ -n "$Y_SHARE_PATH" ] && \
        [ -d "$Y_SHARE_PATH" ] && \
        [ -n "$Y_SHARE_SDDL" ]; then

        f_message "$i_applying_permissions_to_share : $Y_SHARE_NAME"

        "$v_samba_tool_bin" ntacl set "$Y_SHARE_SDDL" "$Y_SHARE_PATH" || true

    fi

    # backup idmap
    if [ "$v_is_domain_controller" = "yes" ] ; then

        f_message "$i_backup : idmap.ldb"

        "$v_tdbbackup_bin" -s .bak "$v_idmap" || true
        cp "${v_idmap}.bak" "${v_sysvol}idmap.ldb" || true

    fi

else

    : # add here all your post start logic that will always run, except on the first run

fi


#
# ============ [ keep running ] ============
# 


f_stay_and_exit

