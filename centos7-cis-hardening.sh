#! /bin/bash
# CIS Benchmark hardening script for CentOS7

# Create /etc/modprobe.d/CIS.conf
# CIS 1.1.1.1 - 1.1.1.8
sudo touch /etc/modprobe.d/CIS.conf

sudo cat <<EOT > /etc/modprobe.d/CIS.conf
#!/bin/bash
install hfs /bin/true
install jffs2 /bin/true
install freevxfs /bin/true
install cramfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOT

# Change file permissions to root
sudo chown root /etc/modprobe.d/CIS.conf
sudo chgrp root /etc/modprobe.d/CIS.conf

# CIS 1.3.1 check for AIDE package
sudo yum -y install aide
aide --init

# CIS 1.3.2
crontab -u root -e
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab


#CIS 1.4.1
sudo chmod 600 /boot/grub2/grub.cfg

#CIS 1.5.1
echo "* hard core 0" >> /etc/security/limits.conf


# CIS xinetd
if [ -d "/etc/xinetd.d" ]; then
  # CIS 2.1.1
  if [ -f "/etc/xinetd.d/chargen-dgram" ]; then
    sudo chkconfig chargen-dgram off
  fi
  if [ -f "/etc/xinetd.d/chargen-stream" ]; then
    sudo chkconfig chargen-stream off
  fi
  # CIS 2.1.2
  if [ -f "/etc/xinetd.d/daytime-dgram" ]; then
    sudo chkconfig daytime-dgram off
  fi
  if [ -f "/etc/xinetd.d/daytime-stream" ]; then
    sudo chkconfig daytime-stream off
  fi
  # CIS 2.1.3
  if [ -f "/etc/xinetd.d/discard-dgram" ]; then
    sudo chkconfig discard-dgram off
  fi
  if [ -f "/etc/xinetd.d/discard-stream" ]; then
    sudo chkconfig discard-stream off
  fi
  # CIS 2.1.4
  if [ -f "/etc/xinetd.d/echo-dgram" ]; then
    sudo chkconfig echo-dgram off
  fi
  if [ -f "/etc/xinetd.d/echo-stream" ]; then
    sudo chkconfig echo-stream off
  fi
  # CIS 2.1.5
  if [ -f "/etc/xinetd.d/time-dgram" ]; then
    sudo chkconfig time-dgram off
  fi
  if [ -f "/etc/xinetd.d/time-stream" ]; then
    sudo chkconfig time-stream off
  fi
  # CIS 2.1.6
  if [ -f "/etc/xinetd.d/tftp" ]; then
    sudo chkconfig tftp off
  fi
  # CIS 2.1.7
  sudo systemctl disable xinetd
fi

# CIS 2.2.1.1
if [ ! -f "/etc/ntp.conf" ]; then
  sudo yum -y yum install ntp
else
  echo "CIS 2.2.1.2 - ntp is installed"
fi

if [ ! -f "/etc/chrony.conf" ]; then
  sudo yum -y yum install chrony
else
  echo "CIS 2.2.1.2 - chrony or ntp is installed"
fi

# CIS 2.2.1.2 NTP is confiugred
if [ -f "/etc/ntp.conf" ]; then
  grep -q "restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf
  if [ `echo $?` == 1 ]; then
    echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
  fi
  grep -q "restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf
  if [ `echo $?` == 1 ]; then
    echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
  fi
  if [ -f "/etc/sysconfig/ntpd" ]; then
    grep "^OPTIONS=\"-u ntp:ntp\"" /etc/sysconfig/ntpd
    if [ `echo $?` == 1 ]; then
      echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd
    fi
  fi
  if [ -f  "/usr/lib/systemd/system/ntpd.service" ]; then
    grep "^ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS" /usr/lib/systemd/system/ntpd.service
    if [ `echo $?` == 1]; then
      echo "ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS" >> /usr/lib/systemd/system/ntpd.service
      systemctl daemon-reload
    fi
  egrep "^(server|pool)" /etc/ntp.conf
  if [ `echo $?` == 1]; then
    echo "server 0.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 1.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 2.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 3.centos.pool.ntp.org iburst" >> /etc/ntp.conf
  fi
fi

# CIS 2.2.1.3 chrony is configured
if [ -f "/etc/chrony.conf"]; then
  if [ -f "/etc/sysconfig/chronyd"]; then
    grep "^OPTIONS=\"-u chrony\"" /etc/sysconfig/chronyd
    if [ `echo $?` == 1]; then
      echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd
    fi
  fi
  egrep "^(server|pool)" /etc/ntp.conf
  if [ `echo $?` == 1 ]; then
    echo "server 0.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 1.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 2.centos.pool.ntp.org iburst" >> /etc/ntp.conf
    echo "server 3.centos.pool.ntp.org iburst" >> /etc/ntp.conf
  fi
fi

# CIS 2.2.7 Ensure NFS and RPC are not enabled
if [ -f "/etc/systemd/system/multi-user.target.wants/nfs-server.service"]; then
  sudo systemctl disable nfs
  sudo systemctl disable nfs-server
fi
if [ -f "/etc/systemd/system/sockets.target.wants/rpcbind.socket"]; then
  systemctl disable rpcbind
fi

# CIS 3.1.2 Ensure packet redirect sending is disabled
ln -s /etc/sysctl.conf /etc/sysctl.d/sysctl.conf

grep 0 /proc/sys/net/ipv4/conf/all/send_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_send_all = grep "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_send_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_send_all ]; then
      echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.route.flush=1
fi

grep 0 /proc/sys/net/ipv4/conf/default/send_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_send_default = grep "net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_send_default ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_send_default ]; then
      echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.2.2 Ensure ICMP redirects are not accepted
grep 0 /proc/sys/net/ipv4/conf/all/accept_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_all = grep "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_all ]; then
      echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.route.flush=1
fi

grep 0 /proc/sys/net/ipv4/conf/default/accept_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_default = grep "net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_default ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_default ]; then
      echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.2.3 Ensure secure ICMP redirects are not accepted
grep 0 /proc/sys/net/ipv4/conf/all/secure_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_all = grep "net.ipv4.conf.all.secure_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_all ]; then
      echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

grep 0 /proc/sys/net/ipv4/conf/default/accept_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_default = grep "net.ipv4.conf.default.secure_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_default ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_default ]; then
      echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.2.4 Ensure suspicious packets are logged
grep 1 /proc/sys/net/ipv4/conf/all/log_martians
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_all = grep "net.ipv4.conf.all.log_martians = 1" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_all ]; then
      echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
    fi
  fi

  sudo sysctl -w net.ipv4.conf.all.log_martians=1
  sudo sysctl -w net.ipv4.route.flush=1
fi

grep 1 /proc/sys/net/ipv4/conf/default/log_martians
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_default = grep "net.ipv4.conf.default.log_martians = 1" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_default ] || [ ! -z $sysctld_var_accept_default_d ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_default ]; then
      echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv4.conf.default.log_martians=1
  sudo sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.3.1 Ensure IPv6 router advertisements are not accepted
grep 0 /proc/sys/net/ipv6/conf/all/accept_ra
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_all = grep "net.ipv6.conf.all.accept_ra = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_all ]; then
      echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv6.conf.all.accept_ra=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

grep 0 /proc/sys/net/ipv6/conf/default/accept_ra
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_default = grep "net.ipv6.conf.default.accept_ra = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_default ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_default ]; then
      echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
    fi
  fi

  sudo sysctl -w net.ipv6.conf.default.accept_ra=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.3.2 Ensure IPv6 redirects are not accepted
grep 0  /proc/sys/net/ipv6/conf/all/accept_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_all = grep "net.ipv6.conf.all.accept_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_all ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_all ]; then
      echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    fi
  fi
  sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

grep 0  /proc/sys/net/ipv6/conf/default/accept_redirects
if [ `echo $?` == 1 ]; then
  sysctl_var_accept_default = grep "net.ipv6.conf.default.accept_redirects = 0" /etc/sysctl.conf
  if [ ! -z $sysctl_var_accept_default ]; then
    if [ -f "/etc/sysctl.conf" ] && [ ! -z $sysctl_var_accept_default ]; then
      echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    fi
  fi

  sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
  sudo sysctl -w net.ipv4.route.flush=1
fi

# CIS 3.3.3 Ensure IPv6 is disabled
grep ipv6.disable /etc/default/grub
if [ `echo $?` == 1 ]; then
  sudo sed -i "s/GRUB_CMDLINE_LINUX=\"\(.*\)\"/GRUB_CMDLINE_LINUX=\"\1 ipv6.disable=1\"/" /etc/default/grub
  sudo -i
  grub2-mkconfig > /boot/grub2/grub.cfg
  exit
fi

# CIS 3.4.3 Ensure /etc/hosts.deny is configured
egrep  "^ALL: ALL"  /etc/hosts.deny
if [ `echo $?` == 1 ]; then
  echo "ALL: ALL" >> /etc/hosts.deny
fi

# CIS 3.5.1 Ensure DCCP is disabled - added to CIS 1.1.1.1 - 1.1.1.8 section
# CIS  3.5.2 Ensure SCTP is disabled - added to CIS 1.1.1.1 - 1.1.1.8 section
# CIS 3.5.3 Ensure RDS is disabled - added to CIS 1.1.1.1 - 1.1.1.8 section
# CIS 3.5.4 Ensure TIPC is disabled - added to CIS 1.1.1.1 - 1.1.1.8 section

# CIS 4.1.1.2 Ensure system is disabled when audit logs are full
egrep "^space_left_action = email" /etc/audit/auditd.conf
if [`echo $?` == 1 ]; then
  sed -i "/^space_left_action =/ s/= .*/= email/" /etc/audit/auditd.conf
fi
egrep "^action_mail_acct = root" /etc/audit/auditd.conf
if [`echo $?` == 1 ]; then
  sed -i "/^action_mail_acct =/ s/= .*/= root/" /etc/audit/auditd.conf
fi

egrep "^admin_space_left_action = halt" /etc/audit/auditd.conf
if [`echo $?` == 1 ]; then
  sed -i "/^admin_space_left_action =/ s/= .*/= halt/" /etc/audit/auditd.conf
fi

# CIS 4.1.1.3 Ensure audit logs are not automatically deleted
egrep "^max_log_file_action  = keep_logs" /etc/audit/auditd.conf
if [`echo $?` == 1 ]; then
  sed -i "/^max_log_file_action =/ s/= .*/= keep_logs/" /etc/audit/auditd.conf
fi

# CIS 4.1.10 Ensure discretionary access control permission modification events are collected
os_version=`file /usr/bin/file`
grep "\-k perm_mod" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
grep "\-k access" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.13 Ensure successful file system mounts are collected
grep "\-k mounts" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.14 Ensure file deletion events by users are collected
grep "\-k deletes" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.15 Ensure changes to system administration scope (sudoers) is collected
grep "\-k scope" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
    echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/audit.rules
fi

# CIS 4.1.16 Ensure system administrator actions (sudolog) are collected
grep "\-k actions" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
fi

# CIS 4.1.17 Ensure kernel module loading and unloading is collected
grep "\-k modules" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
  else
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.18 Ensure the audit configuration is immutable
grep "\-e 2" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-e 2" >> /etc/audit/audit.rules
fi

# CIS 4.1.4 Ensure events that modify date and time information are collected
grep "\-k time-change" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.5 Ensure events that modify user/group information are collected
grep "\-k identity" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
fi


# CIS 4.1.6 Ensure events that modify the system's network environment are collected
grep "\-k system-locale" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
  if [[ $os_version = *"32-bit"* ]]; then
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/audit.rules
  else
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/audit.rules
  fi
fi

# CIS 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected
grep "\-k MAC-policy" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
    echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
fi

# CIS 4.1.8/4.1.9 Ensure login and logout events are collected
grep "\-k logins" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/run/faillock/ -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/audit.rules
fi
grep "\-k session" /etc/audit/audit.rules
if [ `echo $?` == 1 ]; then
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
fi
