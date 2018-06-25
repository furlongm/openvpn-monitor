# openvpn-monitor


## Summary

openvpn-monitor is a simple python program to generate html that displays the
status of an OpenVPN server, including all current connections. It uses the
OpenVPN management console. It typically runs on the same host as the OpenVPN
server, however it does not necessarily need to.

[![](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)


## Source

The current source code is available on github:

https://github.com/furlongm/openvpn-monitor


## Install Options
  - [virtualenv + pip + gunicorn](#virtualenv--pip--gunicorn)
  - [docker](#docker)
  - [apache](#apache)
  - [deb/rpm](#deb--rpm)


### virtualenv + pip + gunicorn

```shell
# apt-get install gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra   # (debian/ubuntu)
# yum install gcc geoip-devel python-virtualenv python-devel GeoIP-data GeoIP-update   # (centos)
mkdir /srv/openvpn-monitor
cd /srv/openvpn-monitor
virtualenv .
. bin/activate
pip install --upgrade pip
pip install openvpn-monitor gunicorn
gunicorn openvpn-monitor -b 0.0.0.0:80
```

### docker

```shell
docker run -p 80:80 ruimarinho/openvpn-monitor
```

Read the [docker installation instructions](https://github.com/ruimarinho/docker-openvpn-monitor#usage) for details on how to generate a dynamic configuration using only environment variables.


### nginx + uwsgi

#### Install dependencies and configure nginx + uwsgi

##### Debian / Ubuntu

```shell
apt-get install libgeoip-dev nginx uwsgi uwsgi-plugin-python
```

#### Checkout openvpn-monitor

```shell
cd /var/www/
git clone https://github.com/furlongm/openvpn-monitor.git
cd openvpn-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
touch touch_to_reload
```

#### Create uWSGI app config

Example for `/etc/uwsgi/apps-available/openvpn-monitor.ini`

```
[uwsgi]
project = openvpn-monitor
base = /var/www

uid = www-data
gid = www-data

socket = /tmp/%(project).sock
pidfile = /tmp/%(project).pid

plugins = python3
logto = /var/log/uwsgi/app/%(project).log
chdir = %(base)/%(project)
virtualenv = %(chdir)/.venv
module = openvpn-monitor:application

touch-reload = %(chdir)/touch_to_reload
master = true
processes = 10
chmod = 666
vacuum = true
```

#### Create Nginx config

Example for `/etc/uwsgi/apps-available/openvpn-monitor.ini`

```
server {
    listen 80;
    root /var/www/openvpn-monitor;
    access_log /var/log/nginx/openvpn-monitor.access.log;
    error_log /var/log/nginx/openvpn-monitor.error.log warn;
    server_name openvpn-monitor.domain.com openvpn-monitor.domain.com;
    charset utf-8;
    gzip on;
    gzip_static on;
    gzip_proxied any;
    gzip_types application/json application/x-javascript text/css;
    gzip_min_length 1024;
    client_max_body_size 5M;

    location = /robots.txt {
        return 200 "User-Agent: *\nDisallow: /\n";
    }

    location / {
        # restrict by basic auth
        # auth_basic "Restricted Content";
        # auth_basic_user_file /var/www/openvpn-monitor/.htpasswd;
        uwsgi_pass unix:///tmp/openvpn-monitor.sock;
        include uwsgi_params;
        # the uwsgi_params file you installed
    }
    # SSL config here
}
```

#### Configure OpenVPN and OpenVPN-Monitor

See in apache section

#### Enable uWSGI app and Nginx site

```shell
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/
service uwsgi restart
ln -s /etc/nginx/sites-available/openvpn-monitor /etc/nginx/sites-enabled/
service nginx reload
```

### apache

#### Install dependencies and configure apache

##### Debian / Ubuntu

```shell
apt-get -y install python-geoip python-ipaddr python-humanize python-bottle python-semantic-version apache2 libapache2-mod-wsgi git wget geoip-database-extra
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" > /etc/apache2/conf-available/openvpn-monitor.conf
a2enconf openvpn-monitor
systemctl restart apache2
```

##### CentOS

```shell
yum install -y epel-release
yum install -y python-GeoIP python-ipaddr python-humanize python-bottle python-semantic_version httpd mod_wsgi git wget GeoIP-data GeoIP-update
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" > /etc/httpd/conf.d/openvpn-monitor.conf
systemctl restart httpd
```


#### Checkout openvpn-monitor

```shell
cd /var/www/html
git clone https://github.com/furlongm/openvpn-monitor.git
```


#### Configure OpenVPN

Add the following line to your OpenVPN server configuration to run the
management console on 127.0.0.1 port 5555:

```
management 127.0.0.1 5555
```

Refer to the OpenVPN documentation for further information on how to secure
access to the management interface.


#### Configure openvpn-monitor

The example configuration file `/var/www/html/openvpn-monitor/openvpn-monitor.conf`
should give some indication of how to set site name, add a logo, etc. You can
also set a default location (latitude and longitude) for the embedded maps.
If not set, the default location is New York, USA.

Edit `/var/www/html/openvpn-monitor/openvpn-monitor.conf` to match your site.

You should now be able to navigate to `http://myipaddress/openvpn-monitor/`

Note the trailing slash, the images may not appear without it.


### deb / rpm

```shell
TBD
```


### Debugging

openvpn-monitor can be run from the command line in order to test if the html
generates correctly:

```shell
cd /var/www/html/openvpn-monitor
python openvpn-monitor.py
```

Further debugging can be enabled by specifying the `--debug` flag:

```shell
cd /var/www/html/openvpn-monitor
python openvpn-monitor.py -d
```


## License

openvpn-monitor is licensed under the GPLv3, a copy of which can be found in
the COPYING file.


## Acknowledgements

Flags are created by Matthias Slovig (flags@slovig.de) and are licensed under
Creative Commons License Deed Attribution-ShareAlike 3.0 Unported
(CC BY-SA 3.0). See http://flags.blogpotato.de/ for more details.
