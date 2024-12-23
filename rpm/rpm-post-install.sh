#!/bin/sh

apache_conf_file=/etc/httpd/conf.d/openvpn-monitor.conf

if [ ! -e ${apache_conf_file} ] ; then
    cp /etc/openvpn-monitor/apache.conf.example ${apache_conf_file}
fi

site_packages=$(python3 -c 'import site; print(site.getsitepackages()[-1])')
if ! grep ${site_packages} ${apache_conf_file} >/dev/null 2>&1 ; then
    sed -i -e "s#^\(Define openvpn_monitor_pythonpath\).*#\1 ${site_packages}#" ${apache_conf_file}
fi

systemctl enable httpd
systemctl restart httpd

chown :apache /etc/openvpn-monitor/openvpn-monitor.conf.example

semanage port -a -t openvpn_port_t -p tcp 5555
setsebool -P httpd_can_network_connect 1
