# openvpn-monitor


## Summary

openvpn-monitor is a simple python program to generate html that displays the
status of an OpenVPN server, including all current connections. It uses the
OpenVPN management console. It typically runs on the same host as the OpenVPN
server, however it does not necessarily need to.

[![](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)


## Supported Operating Systems
  - Ubuntu 20.04 LTS (focal)
  - Debian 10 (buster)
  - CentOS/RHEL 8


## Source

The current source code is available on github:

https://github.com/furlongm/openvpn-monitor


## Install Options

  - [virtualenv + pip + gunicorn](#virtualenv--pip--gunicorn)
  - [apache](#apache)
  - [docker](#docker)
  - [nginx + uwsgi](#nginx--uwsgi)
  - [deb/rpm](#deb--rpm)

N.B. all CentOS/RHEL instructions assume the EPEL repository has been installed:

```shell
dnf -y install epel-release

```

If selinux is enabled the following changes are required for host/port to work:

```
dnf -y install policycoreutils-python-utils
semanage port -a -t openvpn_port_t -p tcp 5555
setsebool -P httpd_can_network_connect=1
```


### virtualenv + pip + gunicorn

```shell
# apt -y install python3-virtualenv geoip-database geoip-database-extra # (debian/ubuntu)
# dnf -y install python3-virtualenv geolite2-city                       # (centos/rhel)
mkdir /srv/openvpn-monitor
cd /srv/openvpn-monitor
virtualenv -p python3 .
. bin/activate
pip install openvpn-monitor gunicorn
gunicorn openvpn-monitor -b 0.0.0.0:80
```

See [configuration](#configuration) for details on configuring openvpn-monitor.


### apache

#### Install dependencies and configure apache

##### Debian / Ubuntu

```shell
apt -y install git apache2 libapache2-mod-wsgi python3-geoip2 python3-humanize python3-bottle python3-semantic-version geoip-database geoip-database-extra
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" > /etc/apache2/conf-available/openvpn-monitor.conf
a2enconf openvpn-monitor
systemctl restart apache2
```

##### CentOS / RHEL

```shell
dnf -y install git httpd mod_wsgi python3-geoip2 python3-humanize python3-bottle python3-semantic_version geolite2-city
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" > /etc/httpd/conf.d/openvpn-monitor.conf
systemctl restart httpd
```

#### Checkout openvpn-monitor

```shell
cd /var/www/html
git clone https://github.com/furlongm/openvpn-monitor.git
```

See [configuration](#configuration) for details on configuring openvpn-monitor.


### docker

```shell
docker run -p 80:80 ruimarinho/openvpn-monitor
```

Read the [docker installation instructions](https://github.com/ruimarinho/docker-openvpn-monitor#usage)
for details on how to generate a dynamic configuration using only environment
variables.


### nginx + uwsgi

#### Install dependencies

```shell
# apt -y install git gcc nginx uwsgi uwsgi-plugin-python3 virtualenv python3-dev libgeoip-dev geoip-database geoip-database-extra  # (debian/ubuntu)
# dnf -y install git gcc nginx uwsgi uwsgi-plugin-python3 virtualenv python3-devel geoip-devel geolite2-city                       # (centos/rhel)
```

#### Checkout openvpn-monitor

```shell
cd /srv
git clone https://github.com/furlongm/openvpn-monitor.git
cd openvpn-monitor
virtualenv -p python3 .
. bin/activate
pip install -r requirements.txt
```

#### uWSGI app config

Create a uWSGI config: `/etc/uwsgi/apps-available/openvpn-monitor.ini`

```
[uwsgi]
base = /srv
project = openvpn-monitor
logto = /var/log/uwsgi/app/%(project).log
plugins = python3
chdir = %(base)/%(project)
virtualenv = %(chdir)
module = openvpn-monitor:application
manage-script-name = true
mount=/openvpn-monitor=openvpn-monitor.py
```

#### Nginx site config

Create an Nginx config: `/etc/nginx/sites-available/openvpn-monitor`

```
server {
    listen 80;
    location /openvpn-monitor/ {
        uwsgi_pass unix:///run/uwsgi/app/openvpn-monitor/socket;
        include uwsgi_params;
    }
}
```

#### Enable uWSGI app and Nginx site, and restart services

```shell
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/
systemctl restart uwsgi
ln -s /etc/nginx/sites-available/openvpn-monitor /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
systemctl restart nginx
```

See [configuration](#configuration) for details on configuring openvpn-monitor.



### deb / rpm

```shell
TBD
```

## Configuration

### Configure OpenVPN

Add the following line to your OpenVPN server configuration to run the
management console on 127.0.0.1 port 5555, with the management password
in /etc/openvpn/pw-file:

```
management 127.0.0.1 5555 pw-file
```

To run the management console on a socket, with the management password
in /etc/openvpn/pw-file:

```
management socket-name unix pw-file
```

Refer to the OpenVPN documentation for further information on how to secure
access to the management interface.


### Configure openvpn-monitor

Copy the example configuration file `openvpn-monitor.conf.example` to the same
directory as openvpn-monitor.py.

```shell
cp openvpn-monitor.conf.example openvpn-monitor.conf

```

In this file you can set site name, add a logo, set the default map location
(latitude and longitude). If not set, the default location is New York, USA.

Once configured, navigate to `http://myipaddress/openvpn-monitor/`

Note the trailing slash, the images may not appear without it.


### Debugging

openvpn-monitor can be run from the command line in order to test if the html
generates correctly:

```shell
cd /var/www/html/openvpn-monitor
python3 openvpn-monitor.py
```

Further debugging can be enabled by specifying the `--debug` flag:

```shell
cd /var/www/html/openvpn-monitor
python3 openvpn-monitor.py -d
```


## License

openvpn-monitor is licensed under the GPLv3, a copy of which can be found in
the COPYING file.


## Acknowledgements

Flags are created by Matthias Slovig (flags@slovig.de) and are licensed under
Creative Commons License Deed Attribution-ShareAlike 3.0 Unported
(CC BY-SA 3.0). See http://flags.blogpotato.de/ for more details.
