#!/bin/bash

# this script is to remediate compliance findings in linux 2 instances
yum update -y

################################################
### - Setting up EST time zone
################################################
sed -i "s/\"UTC\"/\"America\/New_York\"/" /etc/sysconfig/clock
ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

#################################################
### - modprobe file System/CIS file changes 
#################################################
## remove the existing CIS file
rm /etc/modprobe.d/CIS.conf
rm /etc/sysctl.d/CIS.conf

### 1.1.1.1 Ensure mounting of cramfs filesystems is disabled 
echo "install cramfs /bin/true " >> /etc/modprobe.d/CIS.conf
##Run the following command to unload the cramfs module
rmmod cramfs

### 1.1.1.2 Ensure mounting of hfs filesystems is disabled - modprobe 
echo "install hfs /bin/true " >> /etc/modprobe.d/CIS.conf
##Run the following command to unload the hfs module
rmmod hfs

### 1.1.1.3 Ensure mounting of hfsplus filesystems is disabled - modprobe 
echo "install hfsplus /bin/true " >> /etc/modprobe.d/CIS.conf
##Run the following command to unload the hfsplus module
rmmod hfsplus

### 1.1.1.4 Ensure mounting of squashfs filesystems is disabled - modprobe  
echo "install squashfs /bin/true " >> /etc/modprobe.d/CIS.conf
##Run the following command to unload the squashfs module
rmmod squashfs

### 1.1.1.5 Ensure mounting of udf filesystems is disabled - modprobe 
echo "install udf /bin/true " >> /etc/modprobe.d/CIS.conf
##Run the following command to unload the udf module
rmmod udf

### 1.1.2 Ensure /tmp is configured
systemctl unmask tmp.mount systemctl enable tmp.mount

#################################################
### Advanced Intrusion Detection Environment (AIDE)
#################################################
### 1.3.1 Ensure AIDE is installed
yum install aide -y
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

### 1.3.2 Ensure filesystem integrity is regularly checked
## remove any existing schedule for root
crontab -u root -r
# checking is done at 5 AM -> adjust as per need in next command
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root

################################################
### Boot setting
#################################################
### 1.4.1 Ensure permissions on bootloader config are configured
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

### 1.4.2 Ensure authentication required for single user mode
### TBD

#################################################
### Additional process hardening
#################################################
### 1.5.1 Ensure core dumps are restricted - /etc/sysctl.conf, /etc/sysctl.d/*
###	1.5.1 Ensure core dumps are restricted - limits.conf, limits.d/*
cp /etc/security/limits.conf /etc/security/limits.conf.`date +%d%m%Y_%H%M%S` 
echo "* hard core 0" >> /etc/security/limits.conf
echo "* hard core 0" >> /etc/sysctl.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

#################################################
### Banner
#################################################
### 1.7.1.1 Ensure message of the day is configured properly - banner_check
### 1.7.1.2 Ensure local login warning banner is configured properly
### 1.7.1.3 Ensure remote login warning banner is configured properly

echo -e "You are accessing a U.S. Government information system, which includes:\n(1) this computer,\n(2) this computer network,\n(3) all computers connected to this network and\n(4) all devices and storage media attached to this network or to a computer on this network.\n\nThis information system is provided for U.S. Government-authorized use only. Unauthorized or improper use or access of this system may result in disciplinary action, as well as civil and criminal penalties. By using this information system, you understand and consent to the following:\nYou have no reasonable expectation of privacy when you use this information system; this includes any communications or data transiting, stored on, originated from or directed to this information system.\nAt any time, and for any lawful government purpose, the government may monitor, intercept, search and seize any communication or data transiting, stored on, originated from or directed to or from this information system.\nThe government may disclose or use any communications or data transiting, stored on, originated from or directed to or from this information system for any lawful government purpose.\n\nYou are NOT authorized to process classified information.\n" > /etc/issue.net
cp -f /etc/issue.net /etc/issue
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config 

update-motd --disable
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

### 2.1.1.3 Ensure chrony is configured - OPTIONS 
cp /etc/chrony.conf /etc/chrony.conf.`date +%d%m%Y_%H%M%S` 
echo "server 10.0.0.2" >> /etc/chrony.conf

sed -i "s/\"\"/\"-u chrony\"/" /etc/sysconfig/chronyd

### 2.1.7 Ensure NFS and RPC are not enabled - rpcbind 
systemctl disable nfs 
systemctl disable nfs-server 
systemctl disable rpcbind 

### 2.1.15 Ensure mail transfer agent is configured for local-only mode 
sed -i "s/inet_interfaces = localhost/inet_interfaces = loopback-only/" /etc/postfix/main.cf
 
#################################################
### Configure Network Params
#################################################
### 3.1.1 Ensure IP forwarding is disabled  
### 3.1.2 Ensure packet redirect sending is disabled 
### 3.2.1 Ensure source routed packets are not accepted 
### 3.2.2 Ensure ICMP redirects are not accepted
### 3.2.3 Ensure secure ICMP redirects are not accepted
### 3.2.4 Ensure suspicious packets are logged
### 3.2.5 Ensure broadcast ICMP requests are ignored
### 3.2.6 Ensure bogus ICMP responses are ignored 
### 3.2.7 Ensure Reverse Path Filtering is enabled 
### 3.2.8 Ensure TCP SYN Cookies is enabled 
### 3.2.9 Ensure IPv6 router advertisements are not accepted

echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.forwarding = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/CIS.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/CIS.conf

echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/CIS.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/CIS.conf

sysctl -w net.ipv4.ip_forward=0 
sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0 
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.accept_redirects=0 
sysctl -w net.ipv4.conf.default.accept_redirects=0 
sysctl -w net.ipv4.conf.all.secure_redirects=0 
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1 
sysctl -w net.ipv4.conf.default.log_martians=1 
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1 
sysctl -w net.ipv4.conf.default.rp_filter=1 
sysctl -w net.ipv4.tcp_syncookies=1

sysctl -w net.ipv6.conf.all.forwarding=0 
sysctl -w net.ipv6.conf.all.accept_source_route=0 
sysctl -w net.ipv6.conf.default.accept_source_route=0 
sysctl -w net.ipv6.conf.all.accept_redirects=0 
sysctl -w net.ipv6.conf.default.accept_redirects=0 
sysctl -w net.ipv6.conf.all.accept_ra=0 
sysctl -w net.ipv6.conf.default.accept_ra=0 

sysctl -w net.ipv4.route.flush=1 
sysctl -w net.ipv6.route.flush=1 

### 3.3.2 Ensure /etc/hosts.allow is configured
echo "ALL: 10.0.0.0/255.0.0.0" >/etc/hosts.allow
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

### 3.3.3 Ensure /etc/hosts.deny is configured
echo "ALL: ALL" >> /etc/hosts.deny
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

### 3.4.1 Ensure DCCP is disabled
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

### 3.4.2 Ensure SCTP is disabled
echo "install sctp /bin/true " >> /etc/modprobe.d/CIS.conf

### 3.4.3 Ensure RDS protocol is disabled
echo "install rds /bin/true " >> /etc/modprobe.d/CIS.conf

### 3.4.4 Ensure TIPC is disabled
echo "install tipc /bin/true " >> /etc/modprobe.d/CIS.conf

### 3.5.1.1 Ensure default deny firewall policy - Chain FORWARD, INPUT, OUTPUT
### 3.5.1.2 Ensure loopback traffic is configured - INPUT, OUTPUT

### SKIPPED FOR NOW
# iptables -F
# iptables -P INPUT DROP
# iptables -P OUTPUT DROP
# iptables -P FORWARD DROP
# iptables -A INPUT -i lo -j ACCEPT
# iptables -A OUTPUT -o lo -j ACCEPT
# iptables -A INPUT -s 127.0.0.0/8 -j DROP
# iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
# iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
# iptables-save
### SKIPPED

### 3.5.2.1 Ensure IPv6 default deny firewall policy - Chain FORWARD, INPUT, OUTPUT
### 3.5.2.2 Ensure IPv6 loopback traffic is configured - INPUT, OUTPUT

ip6tables -F

ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
ip6tables -A INPUT -i lo -j ACCEPT 
ip6tables -A OUTPUT -o lo -j ACCEPT 
ip6tables -A INPUT -s ::1 -j DROP
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

ip6tables-save


#################################################
### rsyslog
#################################################
cp /etc/rsyslog.conf /etc/rsyslog.conf.`date +%d%m%Y_%H%M%S`

### 4.2.1.3 Ensure rsyslog default file permissions configured
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf

### 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host - rsyslog.conf
echo "*.* @@splunk.company.com:1514" >> /etc/rsyslog.conf

# reload the rsyslogd configuration
pkill -HUP rsyslogd

### 4.2.4 Ensure permissions on all logfiles are configured
find /var/log -type f -exec chmod g-wx,o-rwx {} +

#################################################
### Permissions on cron
#################################################
### 5.1.2 Ensure permissions on /etc/crontab are configured
### 5.1.3 Ensure permissions on /etc/cron.hourly are configured
### 5.1.4 Ensure permissions on /etc/cron.daily are configured
### 5.1.5 Ensure permissions on /etc/cron.weekly are configured
### 5.1.6 Ensure permissions on /etc/cron.monthly are configured
### 5.1.7 Ensure permissions on /etc/cron.d are configured
### 5.1.8 Ensure at/cron is restricted to authorized users 

chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
rm -f /etc/cron.deny
rm -f /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

#################################################
### SSH Protocol
#################################################
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.`date +%d%m%Y_%H%M%S`

### 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

### 5.2.4 Ensure SSH Protocol is set to 2
### 5.2.5 Ensure SSH LogLevel is appropriate - INFO
### 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less
### 5.2.8 Ensure SSH IgnoreRhosts is enabled
### 5.2.9 Ensure SSH HostbasedAuthentication is disabled
### 5.2.10 Ensure SSH root login is disabled
### 5.2.11 Ensure SSH PermitEmptyPasswords is disabled
### 5.2.12 Ensure SSH PermitUserEnvironment is disabled
### 5.2.16 Ensure SSH Idle Timeout Interval is configured - ClientAliveCountMax
### 5.2.16 Ensure SSH Idle Timeout Interval is configured - ClientAliveInterval
### 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less
### 5.2.18 Ensure SSH access is limited
### 5.2.19 Ensure SSH warning banner is configured

echo "Protocol 2" >> /etc/ssh/sshd_config
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
echo "AllowUsers root ec2-user" >> /etc/ssh/sshd_config
echo "AllowGroups root ec2-user" >> /etc/ssh/sshd_config
#echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

#################################################
### Configure password quality
#################################################
### 5.3.1 Ensure password creation requirements are configured - dcredit, lcredit, minlen, ocredit, ucredit
cp /etc/security/pwquality.conf /etc/security/pwquality.conf.`date +%d%m%Y_%H%M%S`

echo "minlen=14" >> /etc/security/pwquality.conf
echo "minclass=1" >> /etc/security/pwquality.conf
echo "maxrepeat=0" >> /etc/security/pwquality.conf
echo "maxclassrepeat=0" >> /etc/security/pwquality.conf
echo "dcredit=-1" >> /etc/security/pwquality.conf
echo "lcredit=-1" >> /etc/security/pwquality.conf
echo "ocredit=-1" >> /etc/security/pwquality.conf
echo "ucredit=-1" >> /etc/security/pwquality.conf

#################################################
### CONFIGURE PAM
#################################################
### 5.3.2 Lockout for failed password attempts - password-auth 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900'
### 5.3.2 Lockout for failed password attempts - password-auth 'auth [success=1 default=bad] pam_unix.so'
### 5.3.2 Lockout for failed password attempts - password-auth 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900'
### 5.3.2 Lockout for failed password attempts - password-auth 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900'
### 5.3.2 Lockout for failed password attempts - system-auth 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900'
### 5.3.2 Lockout for failed password attempts - system-auth 'auth [success=1 default=bad] pam_unix.so'
### 5.3.2 Lockout for failed password attempts - system-auth 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900'
### 5.3.2 Lockout for failed password attempts - system-auth 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900'
### 5.3.3 Ensure password reuse is limited - password-auth pam_pwhistory.so
### 5.3.3 Ensure password reuse is limited - password-auth pam_unix.so
### 5.3.3 Ensure password reuse is limited - system-auth pam_pwhistory.so
### 5.3.3 Ensure password reuse is limited - system-auth pam_unix.so

mv /etc/pam.d/system-auth /etc/pam.d/system-auth.`date +%d%m%Y_%H%M%S`

cat > /etc/pam.d/system-auth <<- EOF
#%PAM-1.0
auth        required      pam_env.so
auth        required      pam_tally2.so deny=3 unlock_time=900
auth        required      pam_faildelay.so delay=900
auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 500 quiet
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        [success=1 default=bad]    pam_unix.so
auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        requisite     pam_succeed_if.so uid >= 500 quiet_success
auth        sufficient    pam_sss.so forward_pass
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 minlen=8 lcredit=1 ucredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3
password    sufficient    pam_unix.so remember=5 sha512 shadow nullok try_first_pass use_authtok
password    required      pam_pwhistory.so remember=5 use_authtok
password    sufficient    pam_sss.so use_authtok
password    sufficient    pam_unix.so remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_systemd.so
session     optional      pam_oddjob_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
EOF

mv /etc/pam.d/password-auth /etc/pam.d/password-auth.`date +%d%m%Y_%H%M%S`

cat > /etc/pam.d/password-auth <<- EOF
#%PAM-1.0
auth        required      pam_env.so
auth        required      pam_tally2.so deny=3 unlock_time=900
auth        required      pam_faildelay.so delay=900
auth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad]   pam_unix.so
auth        [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900
auth        [default=1 ignore=ignore success=ok] pam_succeed_if.so uid >= 500 quiet
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        requisite     pam_succeed_if.so uid >= 500 quiet_success
auth        sufficient    pam_sss.so forward_pass
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 
password    required      pam_pwhistory.so remember=5 use_authtok
password    sufficient    pam_unix.so remember=5 sha512 shadow nullok try_first_pass use_authtok
password    sufficient    pam_sss.so use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_systemd.so
session     optional      pam_oddjob_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
EOF


#################################################
### Configure Password Params
#################################################
### 5.4.1.1 Ensure password expiration is 365 days or less
### 5.4.1.2 Ensure minimum days between password changes is 7 or more
### 5.4.1.4 Ensure inactive password lock is 30 days or less
cp /etc/login.defs /etc/login.defs.`date +%d%m%Y_%H%M%S`

sed -i "s/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t60/" /etc/login.defs
sed -i "s/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/" /etc/login.defs
sed -i "s/PASS_MIN_LEN\t5/PASS_MIN_LEN\t8/" /etc/login.defs

useradd -D -f 30

#################################################
### User mask - 02
#################################################
### 5.4.4 Ensure default user umask is 027 or more restrictive - /etc/profile.d/*.sh

sed -i -r "s/umask\s+[0-7]+(\s*)$/umask 027/g" /etc/bashrc
sed -i -r "s/umask\s+[0-7]+(\s*)$/umask 027/g" /etc/profile
sed -i -r "s/umask\s+[0-7]+(\s*)$/umask 027/g" /etc/profile.d/*.sh

for i in /etc/profile.d/*.sh
do 
   echo "umask 027" >> $i
done

#################################################
### su command restrictions
#################################################
### 5.6 Ensure access to the su command is restricted - /etc/group
cp /etc/pam.d/su /etc/pam.d/su.`date +%d%m%Y_%H%M%S`

echo "auth  required    pam_wheel.so use_uid">> /etc/pam.d/su

usermod -aG wheel root

reboot  