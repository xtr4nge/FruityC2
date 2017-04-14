# FruityC2

This is the initial release for FruityC2 (alpha version). Can be installed on any linux system, but the installation scripts are made for Debian based systems. There are a lot of functionalities that will be include in future releases, and probably a lot of code will be changed, but this version is enough to show FruityC2.

During the development of the initial alpha version, I divided the efforts between the client and the server, but mainly on the client. 

The next steps are to improve the Stager and Agent, add more functionalities and commands, and I will start developing new stagers and agents for other OS systems.

Note: The current Stager and Agent can be only executed on Windows (powershell), but this will be extended in future releases to other systems and file types.
<br><br>

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

## FruityC2 Server

Edit the file `config/settings.conf` and add the IP (from where [FruityC2-Client](https://github.com/xtr4nge/FruityC2-Client) will be used) in section:
<br>
`[souce][[control]]`
<br>
`allow = '127.0.0.1', '10.0.0.1', 'fruityc2-client-ip'`

Then run `./FruityC2.py`

**Note**: To use FruityC2 you need [FruityC2-Client](https://github.com/xtr4nge/FruityC2-Client). You don't need a webserver to use FruityC2-Client, just open `index.html`.
<br><br>

## FruityC2-Client Wiki
https://github.com/xtr4nge/FruityC2-Client/wiki
<br>

<img src="http://i.imgur.com/eSYUw8X.png" w-idth="760">
<br>

## Extra Scripts

### download-modules-extra.sh
This script can be used to download extra modules from the projects: [Empire](https://github.com/adaptivethreat/Empire), [PowerSploit](https://github.com/PowerShellMafia/PowerSploit), [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon) and [Nishang](https://github.com/samratashok/nishang)

### reset.sh
This script can be used to backup the data, logs and config files to then reset the server data.
