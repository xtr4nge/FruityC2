#!/bin/bash
echo "--------------------------------"
echo "Installing FruityC2 dependencies"
echo "--------------------------------"

apt-get -y install python-pip python-requests python-configobj python-flask git

pip install Flask-CORS

echo
echo "--------------------------------"
echo "Downloading FruityC2            "
echo "--------------------------------"

git clone https://github.com/xtr4nge/FruityC2

# SSL
echo
echo "--------------------------------"
echo "Create SSL certificate (default)"
echo "--------------------------------"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout FruityC2/certs/nginx.key -out FruityC2/certs/nginx.crt

echo
echo "--------------------------------"
echo "Downloading FruityC2-Client     "
echo "--------------------------------"

git clone https://github.com/xtr4nge/FruityC2-Client

echo
echo "FruityC2: https://github.com/xtr4nge/FruityC2"
echo "FruityC2-Client: https://github.com/xtr4nge/FruityC2-Client"
echo "Twitter: @xtr4nge, @FruityWifi"
echo "ENJOY!"
echo
