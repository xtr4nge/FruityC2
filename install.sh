#!/bin/bash
echo "--------------------------------"
echo "Installing FruityC2 dependencies"
echo "--------------------------------"

apt-get -y install python-pip python-requests python-configobj python-flask

pip install Flask-CORS

# SSL
echo "--------------------------------"
echo "Create SSL certificate (default)"
echo "--------------------------------"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/nginx.key -out certs/nginx.crt

echo
echo "FruityC2: https://github.com/xtr4nge/FruityC2"
echo "FruityC2-client: https://github.com/xtr4nge/FruityC2-Client"
echo "Twitter: @xtr4nge, @FruityWifi"
echo "ENJOY!"
echo
