# FruityC2

## Install

### Method 1: Standard installer (Server)

script: [install.sh](https://github.com/xtr4nge/FruityC2/blob/master/install.sh)
<br>**Note**: you need to download the master.zip file or to clone the repository (FruityC2).

- You need Debian (or based) installed (or a Live CD version) to use this script.
- Download the zip file from https://github.com/xtr4nge/FruityC2/archive/master.zip
- Unzip the file and run **install.sh** (This script will install all the dependencies)
- Done.
<br><br>

### Method 2: Standalone installer (Server and Client)

script: [install-standalone.sh](https://github.com/xtr4nge/FruityC2/blob/master/install-standalone.sh)

- You need Debian (or based) installed (or a Live CD version) to use this script.
- Download installer-standalone.sh from https://github.com/xtr4nge/FruityC2/
- run **install-standalone.sh** (It will downlaod and install all the dependencies, FruityC2 and FruityC2-Client)
- Done.
<br><br>

## Run

Edit the file "config/settings.conf" and add the IP (from where [FruityC2-Client](https://github.com/xtr4nge/FruityC2-Client) will be used) in `[souce][[control]]` section:
<br>
`allow = '127.0.0.1', '10.0.0.1', 'fruityc2-client-ip'`

Then run `./FruityC2.py`

Note: To use FruityC2 you need [FruityC2-Client](https://github.com/xtr4nge/FruityC2-Client). You don't need a webserver to use FruityC2-Client, just open `index.html`.
<br><br>

## Extra Scripts

### download-modules-extra.sh
This script can be used to download extra modules from the projects: Empire, PowerSploit, PowerShell-AD-Recon and Nishang

### reset.sh
This script can be used to backup the data, logs and config files to then reset the server data.
