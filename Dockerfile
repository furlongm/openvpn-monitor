ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache --virtual .build-dependencies gcc linux-headers geoip-dev musl-dev openssl tar python2-dev py-pip \
  && wget -O /usr/bin/confd https://github.com/kelseyhightower/confd/releases/download/v0.16.0/confd-0.16.0-linux-amd64 \
  && chmod a+x /usr/bin/confd \
  && pip install gunicorn

RUN mkdir /openvpn-monitor 

COPY . /openvpn-monitor

RUN pip install /openvpn-monitor 

RUN apk del .build-dependencies

RUN mkdir -p /usr/share/GeoIP/ \
  && cd /usr/share/GeoIP/ \
  && wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz \
  && gunzip GeoLite2-City.tar.gz \
  && mv GeoLiteCity.dat GeoIPCity.dat

RUN apk add --no-cache geoip

COPY confd /etc/confd
COPY entrypoint.sh /

WORKDIR /openvpn-monitor

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]

CMD ["gunicorn", "openvpn-monitor", "--bind", "0.0.0.0:80"]
