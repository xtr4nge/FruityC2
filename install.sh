#!/bin/bash
echo "--------------------------------"
echo "Installing FruityC2 dependencies"
echo "--------------------------------"

apt-get -y install python-pip python-requests python-configobj python-flask python-pyasn1 python-pyasn1-modules

pip install Flask-CORS

# SSL
echo "--------------------------------"
echo "Create SSL certificate (FruityC2)"
echo "--------------------------------"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/fruityc2.key -out certs/fruityc2.crt
cat certs/fruityc2.key certs/fruityc2.crt > certs/fruityc2.pem

echo
echo "FruityC2: https://github.com/xtr4nge/FruityC2"
echo "FruityC2-client: https://github.com/xtr4nge/FruityC2-Client"
echo "Twitter: @xtr4nge, @FruityWifi"
echo "ENJOY!"
echo
