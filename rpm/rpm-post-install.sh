#!/bin/sh

if [ ! -e /etc/httpd/conf.d/openvpn-monitor.conf ] ; then
    cp /etc/openvpn-monitor/apache.conf.example /etc/httpd/conf.d/openvpn-monitor.conf
fi

site_packages=$(python3 -c 'import site; print(site.getsitepackages()[-1])')
if ! grep ${site-packages} /etc/httpd/conf.d/openvpn-monitor.conf >/dev/null 2>&1 ; then
    sed -i -e "s/^\(Define openvpn_monitor_pythonpath\).*/\1 ${site_packages}" \
    /etc/httpd/conf.d/openvpn-monitor.conf
fi

systemctl enable httpd
systemctl restart httpd

chown :apache /etc/openvpn-monitor/openvpn-monitor.conf

semanage port -a -t openvpn_port_t -p tcp 5555
setsebool -P httpd_can_network_connect 1
