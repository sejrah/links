#!/bin/bash

# this script is to remediate compliance findings in Ubuntu instances
apt update -y
apt upgrade -y

################################################
### - Configuring the Amazon Time Sync Service on Ubuntu
################################################
apt install chrony -y

cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.`date +%d%m%Y_%H%M%S`
sed -i '1s;^;server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n;' /etc/chrony/chrony.conf

/etc/init.d/chrony restart

################################################
### - Setting up EST time zone
################################################
timedatectl set-timezone America/New_York

### UBTU-16-010030 - Ubuntu must display Standard Mandatory DoD Notice and 
### Consent Banner before granting access via command line logon.
### UBTU-16-030210 - Ubuntu must display the Standard Mandatory DoD Notice 
### and Consent Banner before granting access via a ssh logon

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.`date +%d%m%Y_%H%M%S`

echo -e 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.' > /etc/issue

cp -f /etc/issue /etc/issue.net
echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config 

### UBTU-16-030220 - The Ubuntu operating system must not permit direct logons 
### to the root account using remote access via SSH
sed -i 's;^PermitRootLogin.*;PermitRootLogin no;g' /etc/ssh/sshd_config

### UBTU-16-030230 - The Ubuntu operating system must implement DoD-approved 
### encryption to protect the confidentiality of SSH connections.
echo 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr' >> /etc/ssh/sshd_config 

### UBTU-16-030240 - The SSH daemon must be configured to only use MACs 
### employing FIPS 140-2 approved cryptographic hash algorithms.
echo 'MACs hmac-sha2-256,hmac-sha2-512' >> /etc/ssh/sshd_config 

### UBTU-16-030250 - Unattended or automatic login via ssh must not be allowed
echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config 

### UBTU-16-030270 - Ubuntu for network connections associated with SSH must 
### terminate after session or inactivity 
echo 'ClientAliveInterval 600' >> /etc/ssh/sshd_config 
echo 'ClientAliveCountMax 10' >> /etc/ssh/sshd_config 

### UBTU-16-030300 - The SSH daemon must not allow authentication using known hosts authentication
sed -i 's;^#IgnoreUserKnownHosts.*;IgnoreUserKnownHosts yes;g' /etc/ssh/sshd_config

### UBTU-16-030350 - The SSH daemon must not allow compression or must only allow 
### compression after successful authentication.
echo 'Compression no' >> /etc/ssh/sshd_config 

systemctl restart sshd.service

### UBTU-16-010050 - All users must be able to directly initiate a session 
### lock for all connection types.
apt install vlock -y

### UBTU-16-010060 - Ubuntu operating system sessions must be automatically 
### logged out after 15 minutes of inactivity
echo -e 'TMOUT=900' >> /etc/profile.d/autologout.sh
echo -e 'readonly TMOUT' >> /etc/profile.d/autologout.sh
echo -e 'export TMOUT' >> /etc/profile.d/autologout.sh

### UBTU-16-010070 - The Ubuntu operating system must limit the number of 
### concurrent sessions to ten for all accounts and/or account types.
cp /etc/security/limits.conf /etc/security/limits.conf.`date +%d%m%Y_%H%M%S`

sed -i '$ i\*   hard    maxlogins   10\n' /etc/security/limits.conf

### UBTU-16-010140 - The Ubuntu operating system must require the change of at 
### least 8 characters when passwords are changed.
### UBTU-16-010240 - Passwords must have a minimum of 15-characters.
### UBTU-16-010260 - The Ubuntu operating system must prevent the use of 
### dictionary words for passwords.
cp /etc/security/pwquality.conf /etc/security/pwquality.conf.`date +%d%m%Y_%H%M%S`

sed -i 's;^\s*difok\s*=\s*[0-9][0-9]*;difok = 8;g' /etc/security/pwquality.conf
sed -i 's;^\s*minlen\s*=\s*[0-9][0-9]*;minlen = 15;g' /etc/security/pwquality.conf
echo 'dictcheck = 1' >> /etc/security/pwquality.conf

### UBTU-16-010170 - The Ubuntu operating system must employ FIPS 140-2 approved 
### cryptographic hashing algorithms for all created passwords.
### UBTU-16-010230 - Passwords must be prohibited from reuse for a minimum of five generations.

sed -i '$ i\password [success=1 default=ignore] pam_unix.so obscure sha512 remember=5 rounds=5000' /etc/pam.d/common-password

### UBTU-16-010180 - The pam_unix.so module must use a FIPS 140-2 approved cryptographic 
### hashing algorithm for system authentication.
sed -i '$ i\password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5\n' /etc/pam.d/common-password

### UBTU-16-010210 - Passwords for new users must have a 24 hours/1 day minimum 
### password lifetime restriction.
### UBTU-16-010220 - Passwords for new users must have a 60-day maximum password lifetime restriction.
### UBTU-16-010640 - Default permissions must be defined in such a way that 
### all authenticated users can only read and modify their own files.
### UBTU-16-010730 - All local interactive user accounts, upon creation, must be assigned a home directory.
cp /etc/login.defs /etc/login.defs.`date +%d%m%Y_%H%M%S`

sed -i 's;^\s*PASS_MIN_DAYS\s*[0-9][0-9]*;PASS_MIN_DAYS   1;g' /etc/login.defs
sed -i 's;^\s*PASS_MAX_DAYS\s*[0-9][0-9]*;PASS_MAX_DAYS   60;g' /etc/login.defs
sed -i 's;^\s*UMASK.*;UMASK 077\nCREATE_HOME yes;g' /etc/login.defs

### UBTU-16-010250 - The Ubuntu operating system must not have accounts 
### configured with blank or null passwords.
### UBTU-16-010290 - Ubuntu must lock an account until locked account 
### is released by an administrator when three unsuccessful logon attempts.
### UBTU-16-010320 - Ubuntu must enforce a delay of at least 4 seconds 
### between logon prompts following a failed logon attempt.
### UBTU-16-010690 - Pluggable Authentication Module (PAM) must 
### prohibit the use of cached authentications after one day.

sed -i '/pam_unix.so.*nullok/ d' /etc/pam.d/common-auth
sed -i '$ i\auth    required    pam_tally2.so   onerr=fail  deny=3' /etc/pam.d/common-auth
sed -i '$ i\auth required pam_faildelay.so delay=4000000' /etc/pam.d/common-auth
###sed -i '$ i\session  required timestamp_timeout = 86400\n' /etc/pam.d/common-auth

### 

### UBTU-16-010280 - Account identifiers (individuals, groups, roles, 
### and devices) must disabled after 35 days of inactivity.
useradd -D -f 35

### UBTU-16-010300 - The Ubuntu operating system must require users to 
### re- authenticate for privilege escalation and changing roles - sudoers.d

### DO NOT MAKE THE FOLLOWING CHANGE AS IT PREVENTS SUDO as ROOT
###sed -i 's;NOPASSWD:ALL;;g' /etc/sudoers.d/90-cloud-init-users

### UBTU-16-010340 - The Ubuntu operating system must display the date and 
### time of the last successful account logon upon logon.
cp /etc/pam.d/login /etc/pam.d/login.`date +%d%m%Y_%H%M%S`

sed -i 's;.*pam_lastlog.so.*;session required    pam_lastlog.so  showfailed;g' /etc/pam.d/login

### UBTU-16-010540 - File integrity tool must notify system administrator 
### when changes to baseline or anomalies are discovered - silentreports
cp /etc/default/aide /etc/default/aide.`date +%d%m%Y_%H%M%S`

sed -i 's;^.*SILENTREPORTS.*;SILENTREPORTS=no;g' /etc/default/aide

### UBTU-16-010550 - The Ubuntu operating system must use cryptographic 
### mechanisms to protect the integrity of audit tools
cp /etc/aide/aide.conf /etc/aide/aide.conf.`date +%d%m%Y_%H%M%S`

echo -e '\n# Audit Tools
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/audispd p+i+n+u+g+s+b+acl+xattr+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattr+sha512' >> /etc/aide/aide.conf

echo -e 'SILENTREPORTS=no' >> /etc/aide/aide.conf

### UBTU-16-010570 - Advance package Tool (APT) must remove all software 
### components after updated versions have been installed.
sed -i 's;^.*Remove-Unused-Dependencies.*;Unattended-Upgrade::Remove-Unused-Dependencies "true"\;;g' /etc/apt/apt.conf.d/50unattended-upgrades

### UBTU-16-010750 - All local interactive user home directories 
### must have mode 0750 or less permissive.
chmod 0750 /home/ubuntu

### UBTU-16-010770 - All local initialization files must have mode 0740 or less permissive
chmod 0740 /home/ubuntu/.*
chmod o-r /root/.*
chmod o-r /home/ssm-user/.*

### UBTU-16-010960 - The /var/log directory must have mode 0770 or less permissive.
chmod 0770 /var/log

### UBTU-16-011000 - Library files must have mode 0755 or less permissive.
chmod 0755 -R /usr/lib/mesos
chmod 0755 -R /usr/lib/python*
chmod 0755 /lib/systemd/system/mesos*

### UBTU-16-020060 - The audit system must take appropriate action when the audit storage volume is full.
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.`date +%d%m%Y_%H%M%S`
sed -i 's;.*disk_full_action.*;disk_full_action = SYSLOG;g' /etc/audit/auditd.conf

### UBTU-16-020070 - The audit system must take appropriate action when audit storage is full.
echo -e 'disk_full_action = syslog' >> /etc/audisp/audisp-remote.conf

### UBTU-16-020080 - Off-loading audit records to another system must be authenticated.
echo -e 'enable_krb5 = yes' >> /etc/audisp/audisp-remote.conf

### UBTU-16-020220 - The audit records must be off-loaded onto a different system 
### or storage media from the system being audited.
echo -e 'remote_server = 10.0.1.2' >> /etc/audisp/audisp-remote.conf

### UBTU-16-030430 - The audit system must take appropriate action when the 
### network cannot be used to off-load audit records.
echo -e 'network_failure_action = syslog' >> /etc/audisp/audisp-remote.conf

### UBTU-16-020210 - The audit event multiplexor must be configured to 
### off-load audit logs onto a different system or storage media
echo -e 'active = yes' >> /etc/audisp/plugins.d/au-remote.conf

### UBTU-16-020350 - The audit system must be configured to audit the 
### execution of privileged functions
### UBTU-16-020360 - Successful/unsuccessful uses of the su command must generate an audit record.
### UBTU-16-020370 - Successful/unsuccessful uses of the chfn command must generate an audit record.
### UBTU-16-020380 - Successful/unsuccessful uses of the mount command must generate an audit record.
### UBTU-16-020390 - Successful/unsuccessful uses of the umount command must generate an audit record.
### UBTU-16-020400 - Successful/unsuccessful uses of the ssh-agent command must generate an audit record.
### UBTU-16-020410 - Successful/unsuccessful uses of the ssh-keysign command must generate an audit record.
### UBTU-16-020450 - The audit system must be configured to audit any usage of the kmod command.
### UBTU-16-020460 - The audit system must be configured to audit any usage of the setxattr system call
### UBTU-16-020470 - The audit system must be configured to audit any usage of the lsetxattr system call
### UBTU-16-020480 - The audit system must be configured to audit any usage of the fsetxattr system call
### UBTU-16-020490 - The audit system must be configured to audit any usage of the removexattr system call
### UBTU-16-020500 - The audit system must be configured to audit any usage of the lremovexattr system call 
### UBTU-16-020510 - The audit system must be configured to audit any usage of the fremovexattr system call
### UBTU-16-020520 - Successful/unsuccessful uses of the chown command must generate an audit record.
### UBTU-16-020530 - Successful/unsuccessful uses of the fchown command must generate an audit record.
### UBTU-16-020540 - Successful/unsuccessful uses of the fchownat command must generate an audit record.
### UBTU-16-020550 - Successful/unsuccessful uses of the lchown command must generate an audit record.
### UBTU-16-020560 - Successful/unsuccessful uses of the chmod command must generate an audit record.
### UBTU-16-020570 - Successful/unsuccessful uses of the fchmod command must generate an audit record.
### UBTU-16-020580 - Successful/unsuccessful uses of the fchmodat command must generate an audit record.
### UBTU-16-020590 - Successful/unsuccessful uses of the open command must generate an audit record
### UBTU-16-020600 - Successful/unsuccessful uses of the truncate command must generate an audit record
### UBTU-16-020610 - Successful/unsuccessful uses of the ftruncate command must generate an audit record 
### UBTU-16-020620 - Successful/unsuccessful uses of the creat command must generate an audit record 
### UBTU-16-020630 - Successful/unsuccessful uses of the openat command must generate an audit record
### UBTU-16-020640 - Successful/unsuccessful uses of the open_by_handle_at command must generate an audit record
### UBTU-16-020650 - Successful/unsuccessful uses of the sudo command must generate an audit record
### UBTU-16-020660 - Successful/unsuccessful uses of the sudoedit command must generate an audit record
### UBTU-16-020670 - Successful/unsuccessful uses of the chsh command must generate an audit record
### UBTU-16-020680 - Successful/unsuccessful uses of the newgrp command must generate an audit record
### UBTU-16-020690 - Successful/unsuccessful uses of the chcon command must generate an audit record
### UBTU-16-020700 - Successful/unsuccessful uses of the apparmor_parser command must generate an audit record
### UBTU-16-020710 - Successful/unsuccessful uses of the setfacl command must generate an audit record
### UBTU-16-020720 - Successful/unsuccessful uses of the chacl command must generate an audit record
### UBTU-16-020760 - Successful/unsuccessful uses of the passwd command must generate an audit record
### UBTU-16-020770 - Successful/unsuccessful uses of the unix_update command must generate an audit record
### UBTU-16-020780 - Successful/unsuccessful uses of the gpasswd command must generate an audit record
### UBTU-16-020790 - Successful/unsuccessful uses of the chage command must generate an audit record
### UBTU-16-020800 - Successful/unsuccessful uses of the usermod command must generate an audit record
### UBTU-16-020810 - Successful/unsuccessful uses of the crontab command must generate an audit record.
### UBTU-16-020820 - Successful/unsuccessful uses of the pam_timestamp_check command must generate an audit record
### UBTU-16-020830 - Successful/unsuccessful uses of the init_module command must generate an audit record
### UBTU-16-020840 - Successful/unsuccessful uses of the finit_module command must generate an audit record
### UBTU-16-020850 - Successful/unsuccessful uses of the delete_module command must generate an audit record

cp /etc/audit/audit.rules /etc/audit/audit.rules.`date +%d%m%Y_%H%M%S`

echo -e '-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh' >> /etc/audit/audit.rules

echo -e '-w /bin/kmod -p x -k modules' >> /etc/audit/audit.rules

# remove the existing perm_mod values
sed -i 's;.*b64.*attr.*perm_mod;;g' /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules
echo -e '-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab' >> /etc/audit/audit.rules

echo -e '-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng' >> /etc/audit/audit.rules

echo -e '-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng' >> /etc/audit/audit.rules

systemctl restart auditd.service


### UBTU-16-030100 - Ubuntu must compare system clocks every 24 hours 
### with a server synchronized to an authoritative time source
echo -e 'maxpoll = 17 server 0.us.pool.ntp.org iburst' >> /etc/ntp.conf

### UBTU-16-030450 - All remote access methods must be monitored
cp /etc/rsyslog.d/50-default.conf /etc/rsyslog.d/50-default.conf.`date +%d%m%Y_%H%M%S`
echo -e 'auth.*,authpriv.* /var/log/secure daemon.notice /var/log/messages' >> /etc/rsyslog.d/50-default.conf

### UBTU-16-030460 - Cron logging must be implemented
sed -i 's;.*/var/log/cron.log.*;cron.*      /var/log/cron.log;g' /etc/rsyslog.d/50-default.conf

cp /etc/sysctl.conf /etc/sysctl.conf.`date +%d%m%Y_%H%M%S`

### UBTU-16-030540 - The Ubuntu operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.default.accept_source_route=0

### UBTU-16-030560 - Ubuntu must prevent Internet Protocol version 4 Internet Control Message Protocol redirect messages from being accepted
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.default.accept_redirects=0 

### UBTU-16-030570 - The Ubuntu operating system must ignore Internet Protocol version 4 Internet Control Message Protocol redirect messages
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0 

### UBTU-16-030580 - Ubuntu must not allow interfaces to perform Internet Protocol version 4 Internet Control Message Protocol redirects
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.default.send_redirects=0

### UBTU-16-030590 - The Ubuntu operating system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol redirects
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0 

### UBTU-16-030600 - The Ubuntu operating system must not be performing packet forwarding unless the system is a router
echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0 

### UBTU-16-030620 - The Ubuntu operating system must be configured to prevent unrestricted mail relaying.
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject'

### UBTU-16-030800 - The Ubuntu operating system must have the packages required for multifactor authentication to be installed
apt install libpam-pkcs11 -y

### UBTU-16-030810 - The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials
apt-get install opensc-pkcs11 -y

apt autoremove -y

### installing mcAfee EPO agent
wget https://<s3 bucket name>.s3.amazonaws.com/McAfeeSmartInstall.sh
chmod u+x McAfeeSmartInstall.sh
./McAfeeSmartInstall.sh
/opt/McAfee/cma/bin/maconfig -enforce -noguid
/etc/init.d/ma stop

### installing splunk forwarder
wget -O splunkforwarder-8.1.2-545206cc9f70-Linux-x86_64.tgz 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.1.2&product=universalforwarder&filename=splunkforwarder-8.1.2-545206cc9f70-Linux-x86_64.tgz&wget=true'
tar xvzf splunkforwarder-8.1.2-545206cc9f70-Linux-x86_64.tgz -C /opt
chown root:root -R /opt/splunkforwarder
/opt/splunkforwarder/bin/splunk start --accept-license

/opt/splunkforwarder/bin/splunk enable boot-start
/opt/splunkforwarder/bin/splunk add forward-server 10.255.246.8:9997
/opt/splunkforwarder/bin/splunk set deploy-poll 10.255.246.10:8089
/opt/splunkforwarder/bin/splunk enable listen  9997
/opt/splunkforwarder/bin/splunk stop
/opt/splunkforwarder/bin/splunk clone-prep-clear-config


reboot  