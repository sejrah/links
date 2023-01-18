#!/bin/bash

# this script is to remediate compliance findings in Ubuntu instances
apt update -y
apt upgrade -y

################################################
### - Configuring the Amazon Time Sync Service on Ubuntu
################################################
### 2.1.1.3 Ensure chrony is configured - server
apt install chrony -y

cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.`date +%d%m%Y_%H%M%S`
sed -i '1s;^;server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n;' /etc/chrony/chrony.conf

/etc/init.d/chrony restart

################################################
### - Setting up EST time zone
################################################
timedatectl set-timezone America/New_York

### Consent Banner before granting access via command line logon.
### and Consent Banner before granting access via a ssh logon
### 1.7.2 Ensure local login warning banner is configured properly - banner
### 1.7.3 Ensure remote login warning banner is configured properly - banner
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.`date +%d%m%Y_%H%M%S`

echo -e 'You are accessing a U.S. Government information system, which includes: (1) this computer, (2) this computer network, (3) all computers connected to this network and (4) all devices and storage media attached to this network or to a computer on this network.  This information system is provided for U.S. Government-authorized use only. Unauthorized or improper use or access of this system may result in disciplinary action, as well as civil and criminal penalties. By using this information system, you understand and consent to the following: You have no reasonable expectation of privacy when you use this information system; this includes any communications or data transiting, stored on, originated from or directed to this information system. At any time, and for any lawful government purpose, the government may monitor, intercept, search and seize any communication or data transiting, stored on, originated from or directed to or from this information system. The government may disclose or use any communications or data transiting, stored on, originated from or directed to or from this information system for any lawful government purpose.  You are NOT authorized to process classified information.' > /etc/issue

cp -f /etc/issue /etc/issue.net
echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config


echo '### 1.3.2 Ensure filesystem integrity is regularly checked'
crontab -l|sed "\$a0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"|crontab -

echo '### 1.4.1 Ensure permissions on bootloader config are not overridden - if line'
echo '### 1.4.1 Ensure permissions on bootloader config are not overridden - chmod'
#sed -ri 's/chmods+[0-7][0-7][0-7]s+${grub_cfg}.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
#sed -ri 's/ && ! grep '^password' ${grub_cfg}.new >/dev/null//' /usr/sbin/grub-mkconfig

#if [ 'x${grub_cfg}' != 'x' ] && ! grep '^password' ${grub_cfg}.new >/dev/null; then

#  chmod 444 ${grub_cfg}.new || true

#fi

echo '### 1.4.3 Ensure permissions on bootloader config are configured'
chown root:root /boot/grub/grub.cfg
chmod u-wx,go-rwx /boot/grub/grub.cfg

#echo '### 1.7.4 Ensure permissions on /etc/motd are configured'
#chown root:root $(readlink -e /etc/motd)
#chmod u-x,go-wx $(readlink -e /etc/motd)

echo '### 2.1.16 Ensure rsync service is not installed'
apt purge rsync

echo '### 5.3.22 Ensure SSH MaxSessions is limited'
sed -i 's;^\s*MaxSessions\s*[0-9][0-9]*;MaxSessions   10;g' /etc/ssh/sshd_config

echo '### 5.5.1.1 Ensure minimum days between password changes is configured - login.defs'
sed -i 's;^\s*PASS_MIN_DAYS\s*[0-9][0-9]*;PASS_MIN_DAYS   1;g' /etc/login.defs
sed -i 's;^\s*PASS_MAX_DAYS\s*[0-9][0-9]*;PASS_MAX_DAYS   60;g' /etc/login.defs

echo '### 6.1.6 Ensure permissions on /etc/shadow are configured'
chown root:root /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow

#echo '### 6.2.7 Ensure users dot files are not group or world writable'
#awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(/usr)?/sbin/nologin(/)?$/ && $7!~/(/usr)?/bin/false(/)?$/) { print $1 ' ' $6 }' | while read -r userdir; do
#  if [ -d '$dir' ]; then
#    for file in '$dir'/.*; do
#      if [ ! -h '$file' ] && [ -f '$file' ]; then
#        fileperm=$(stat -L -c '%A' '$file')
#        if [ '$(echo '$fileperm' | cut -c6)' != '-' ] || [ '$(echo '$fileperm' | cut -c9)' != '-' ]; then
#          chmod go-w '$file'
#        fi
#      fi
#    done
#  fi
#done

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F


apt autoremove -y

### installing splunk forwarder
wget -O splunkforwarder-8.2.3-cd0848707637-Linux-x86_64.tgz 'https://download.splunk.com/products/universalforwarder/releases/8.2.3/linux/splunkforwarder-8.2.3-cd0848707637-Linux-x86_64.tgz'
tar xvzf splunkforwarder-8.2.3-cd0848707637-Linux-x86_64.tgz -C /opt
chown root:root -R /opt/splunkforwarder
/opt/splunkforwarder/bin/splunk start --accept-license

/opt/splunkforwarder/bin/splunk enable boot-start
/opt/splunkforwarder/bin/splunk add forward-server 10.255.246.8:9997
/opt/splunkforwarder/bin/splunk set deploy-poll 10.255.246.10:8089
/opt/splunkforwarder/bin/splunk enable listen  9997
/opt/splunkforwarder/bin/splunk stop
/opt/splunkforwarder/bin/splunk clone-prep-clear-config

reboot
