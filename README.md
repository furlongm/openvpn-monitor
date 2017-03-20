# OpenVPN-Monitor


## Summary

OpenVPN-Monitor is a simple python program to generate html that displays the
status of an OpenVPN server, including all current connections. It uses the
OpenVPN management console. It typically runs on the same host as the OpenVPN
server, however it does not necessarily need to.

[![](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)](https://raw.githubusercontent.com/furlongm/openvpn-monitor/gh-pages/screenshots/openvpn-monitor.png)


## Source

The current source code is available on github:

https://github.com/furlongm/openvpn-monitor


## Quick install with virtualenv/pip/gunicorn


```shell
mkdir /srv/openvpn-monitor
cd /srv/openvpn-monitor
virtualenv .
. bin/activate
pip install openvpn-monitor gunicorn
gunicorn openvpn-monitor -b 0.0.0.0:80
```


## Installation

### Install dependencies and configure apache


##### raspberryPi
raspberryPi follows instructions set out in Debian / Ubuntu below, with the exception of the python-semantic-version. With one exception.
You will need to install this manually from PIP using the below command. 
When following the Debian / Ubuntu instructions remember to remove the python-semantic-version item from the apt-get command

```shell
pip install semantic_version
```

#### Debian / Ubuntu
The below will install and configure the web application, applying relative Alias commands to access local resources

```shell
apt-get -y install python-geoip python-ipaddr python-humanize python-bottle python-semantic-version apache2 libapache2-mod-wsgi git wget
echo "Alias /images/ /var/www/html/openvpn-monitor/images/" > /etc/apache2/conf-available/openvpn-monitor.conf
echo "Alias /images/ /var/www/html/openvpn-monitor/js/" >> /etc/apache2/conf-available/openvpn-monitor.conf
echo "Alias /images/ /var/www/html/openvpn-monitor/css/" >> /etc/apache2/conf-available/openvpn-monitor.conf
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" >> /etc/apache2/conf-available/openvpn-monitor.conf
a2enconf openvpn-monitor
systemctl restart apache2
```

#### CentOS

```shell
yum install -y epel-release
yum install -y python-GeoIP python-ipaddr python-humanize python-bottle python-semantic_version httpd mod_wsgi git wget
echo "WSGIScriptAlias /openvpn-monitor /var/www/html/openvpn-monitor/openvpn-monitor.py" > /etc/httpd/conf.d/openvpn-monitor.conf
systemctl restart httpd
```

### Checkout OpenVPN-Monitor

```shell
cd /var/www/html
git clone https://github.com/furlongm/openvpn-monitor.git
```


### Configure OpenVPN

Add the following line to your OpenVPN server configuration to run the
management console on 127.0.0.1 port 5555: (This port is arbitary, you may choose any)

```
management 127.0.0.1 5555
```

Refer to the OpenVPN documentation for further information on how to secure
access to the management interface.


### Download the GeoLite City database

```shell
cd /usr/share/GeoIP/
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
gunzip GeoLiteCity.dat.gz
mv GeoLiteCity.dat GeoIPCity.dat
```


### Configure OpenVPN-Monitor

The example configuration file `/var/www/html/openvpn-monitor/openvpn-monitor.conf.example`
should give some indication of how to set site name, add a logo, etc. You can
also set a default location (latitude and longitude) for the embedded maps.
If not set, the default location is Melbourne, Australia.

Complete the following by editting `/var/www/html/openvpn-monitor/openvpn-monitor.conf` to match your site.

#### OpenVPN-Monitor
The below should help you quickly configure your vpn monitor with relevant settings

| Option           | Default  | Description |
| ---              | ---      | ---         |
| site             | Example  | The name of the monitoring box - Free text, can be anything |
| logo             | None     | Optional logo. This will be displayed in the top right. No default provided |
| latitude         | -37.8067 | Latitude location for the centre of map and marker icon to be set. Requires longitude or no action is taken. |
| longitude        | 144.9635 | Longitude location for the centre of map and marker icon to be set. Requires latitude or no action is taken. |
| Maps             | False    | Will the site display the map|
| geoip_data       | /usr/share/GeoIP/GeoIPCity.dat | GeoLocation data location. Unless you are making locational changes this should not need to be changed. |
| datetime_format  | %a %b %d %H:%M:%S %Y | DateTime format for server display |
| marker           | False    | Display a marker on the map for the OpenVPN-Monitor Box |
| externalip       | 0.0.0.0  |  External IP of the OpenVPN-Monitor box. If latitude and longitude not specified then this is used to locate the Monitor box |
| pervpn_control   | False    |  Display a layer control to turn of element markers per vpn | 
| itemtype_control | False    |  Display a layer control to turn off element markers per connection type |
| allowFullscreen  | False    |  Allow the map to be displayed in FullScreen mode |

Note: If latitude, longitude and externalip all cannot be validated then Melbourne, Australia becomes the default centre and marker location.

#### Per VPN Settings
The below should help you quickly configure connections to vpns

| Option           | Default    | Description |
| ---              | ---        | ---         |
| host             | localhost  | Specifies the IP or DNS name of the VPN management interface to connect. |
| port             | 5555       | Specifies the Port of the management internace to connect. |
| name             | default    | Free Text. The name of the VPN Connection |
| show_disconnect  | False      | Show a button to disconnect clients |
| externalip       | 0.0.0.0    | External IP of the VPN Server. If latitude and longitude not specified then this is used to locate the VPN |
| latitude         | -35.308065 | Latitude location for the vpn marker icon. Requires longitude or no action is taken. |
| longitude        | 149.124521 | Longitude location for the vpn marker icon. Requires Latitude or no action is taken. |
| marker           | False      | Display a marker on the map for the VPN Server |
| connection_lines | False      | Display connection lines between the Server and the Clients. Requires marker to be on for VPN. |

Note: If latitude, longitude and externalip all cannot be validated then Canberra, Australia becomes the default marker location.

### Your Done
You should now be able to navigate to `http://myipaddress/openvpn-monitor`


### Debugging

OpenVPN-Monitor can be run from the command line in order to test if the html
generates correctly:

```shell
cd /var/www/html/openvpn-monitor
python openvpn-monitor.py
```


## License

OpenVPN-Monitor is licensed under the GPLv3, a copy of which can be found in
the COPYING file.


## Acknowledgements

Flags are created by Matthias Slovig (flags@slovig.de) and are licensed under
Creative Commons License Deed Attribution-ShareAlike 3.0 Unported
(CC BY-SA 3.0). See http://flags.blogpotato.de/ for more details.
Fullscreen control provided by https://github.com/brunob/leaflet.fullscreen
Spiderfy (Closeby Marker control) provided by https://github.com/jawj/OverlappingMarkerSpiderfier-Leaflet
