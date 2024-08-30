# openvpn-monitor


## Summary

openvpn-monitor is a flask app that displays the status of OpenVPN servers,
including all current connections. It uses the OpenVPN management console.
It typically runs on the same host as the OpenVPN server, but it can also
manage remote servers.

[![](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)


## Supported Operating Systems
  - Ubuntu 24.04 LTS (noble)
  - Debian 11 (bullseye)
  - Rocky/Alma/RHEL 9


## Source

The current source code is available on github:

https://github.com/furlongm/openvpn-monitor


## Install Options

  - [deb/rpm](#deb--rpm)
  - [virtualenv + pip + gunicorn](#virtualenv--pip--gunicorn)
  - [apache](#apache)
  - [docker](#docker)
  - [nginx + uwsgi](#nginx--uwsgi)

N.B. all Rocky/Alma/RHEL instructions assume the EPEL repository has been installed:

```shell
dnf -y install epel-release
dnf makecache
```

If selinux is enabled the following changes are required for host/port to work:

```
dnf -y install policycoreutils-python-utils
semanage port -a -t openvpn_port_t -p tcp 5555
setsebool -P httpd_can_network_connect 1
```


### virtualenv + pip + gunicorn

```shell
# apt -y install python3-venv           # (debian/ubuntu)
# dnf -y install python3 geolite2-city  # (rocky/alma/rhel)
mkdir /srv/openvpn-monitor
cd /srv/openvpn-monitor
python3 -m venv .venv
. venv/bin/activate
pip install openvpn-monitor gunicorn
gunicorn openvpn_monitor.app -b 0.0.0.0:80
```

See [configuration](#configuration) for details on configuring openvpn-monitor.


### apache

#### Install dependencies and configure apache

##### Debian / Ubuntu

```shell
apt -y install git apache2 libapache2-mod-wsgi-py3 python3-geoip2 python3-humanize python3-flask python3-semver yarnpkg
a2enmod rewrite wsgi
echo "RewriteRule ^/openvpn-monitor$ /openvpn-monitor/ [R,L]" > /etc/apache2/conf-available/openvpn-monitor.conf
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn_monitor/app.py" >> /etc/apache2/conf-available/openvpn-monitor.conf
a2enconf openvpn-monitor
service apache2 restart
```

##### CentOS / RHEL

```shell
dnf -y install git httpd mod_wsgi python3-geoip2 python3-humanize python3-flask python3-semver geolite2-city yarnpkg
echo "RewriteRule ^/openvpn-monitor$ /openvpn-monitor/ [R,L]" > /etc/httpd/conf.d/openvpn-monitor.conf
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn_monitor/app.py" >> /etc/httpd/conf.d/openvpn-monitor.conf
systemctl restart httpd
```

#### Checkout openvpn-monitor

```shell
cd /var/www/html
git clone https://github.com/furlongm/openvpn-monitor
cd openvpn-monitor
yarnpkg --prod --modules-folder openvpn_monitor/static/dist install
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
apt -y install git gcc nginx uwsgi uwsgi-plugin-python3 python3-dev python3-venv libgeoip-dev yarnpkg  # (debian/ubuntu)
dnf -y install git gcc nginx uwsgi uwsgi-plugin-python3 python3-devel geolite2-city yarnpkg            # (centos/rhel)
```

#### Checkout openvpn-monitor

```shell
cd /srv
git clone https://github.com/furlongm/openvpn-monitor
cd openvpn-monitor
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
yarnpkg --prod --modules-folder openvpn_monitor/static/dist install
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
virtualenv = %(chdir)/.venv
module = openvpn-monitor:application
manage-script-name = true
mount=/openvpn-monitor=openvpn_monitor/app.py
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
directory as app.py.

```shell
cp openvpn-monitor.conf.example openvpn_monitor/openvpn-monitor.conf

```

In this file you can set site name, add a logo, set the default map location
(latitude and longitude). If not set, the default location is New York, USA.

Once configured, navigate to `http://myipaddress/openvpn-monitor/`


### Development / Debugging

openvpn-monitor can be run from the command line for development / debugging
purposes:

```shell
cd /var/www/html/openvpn-monitor
flask --app openvpn_monitor/app run --debug
```

## License

openvpn-monitor is licensed under the GPLv3, a copy of which can be found in
the COPYING file.


## Acknowledgements

Flags are created by Matthias Slovig (flags@slovig.de) and are licensed under
Creative Commons License Deed Attribution-ShareAlike 3.0 Unported
(CC BY-SA 3.0). See http://flags.blogpotato.de/ for more details.
