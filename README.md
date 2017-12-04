# FruityC2

This is the initial release for FruityC2 (alpha version). Can be installed on any linux system, but the installation scripts are made for Debian based systems. There are a lot of functionalities that will be include in future releases, and probably a lot of code will be changed, but this version is enough to show FruityC2.

<br>
FruityC2 is a post-exploitation (and open source) framework based on the deployment of agents on compromised machines. Agents are managed from a web interface under the control of an operator.

<br>It works as a command-and-control model and is language and system agnostic. New agents are being developed to expand the capabilities and options for FruityC2.

<br>A web client is used to interact with the FruityC2 API in a client/server mode. The client is a single web page divided into 5 sections: Interact, Listener, Payload, Delivery, Config. These options provide full control and access to the functions included in FruityC2 to create, deliver and interact with a functioning C2 capability.

<br>
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

Edit the file `config/settings.conf` and add the IP (from where FruityC2-Client will be used) in section:
<br>
`[souce][[control]]`
<br>
`allow = '127.0.0.1', '10.0.0.1', 'fruityc2-client-ip'`

<br>

Then run `./FruityC2.py`

Open a browser: https://{FruityC2-IP}:50000/login
<br>user: **admin**
<br>pass: **admin**

<br><br>

## FruityC2-Client Wiki
https://github.com/xtr4nge/FruityC2/wiki
<br>

<img src="http://i.imgur.com/eSYUw8X.png" w-idth="760">
<br>

## Extra Scripts

### download-modules-extra.sh
This script can be used to download extra modules from the projects: [Empire](https://github.com/adaptivethreat/Empire), [PowerSploit](https://github.com/PowerShellMafia/PowerSploit), [PowerShell-AD-Recon](https://github.com/PyroTek3/PowerShell-AD-Recon) and [Nishang](https://github.com/samratashok/nishang)

### reset.sh
This script can be used to backup the data, logs and config files to then reset the server data.
