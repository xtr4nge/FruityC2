#!/bin/bash
echo "--------------------------------"
echo "Downloading Empire PS scripts   "
echo "GitHub: https://github.com/adaptivethreat/Empire"
echo "--------------------------------"

svn export https://github.com/adaptivethreat/Empire/trunk/data/module_source modules/empire #--force

echo
echo "--------------------------------"
echo "Downloading PowerSploit PS scripts "
echo "GitHub: https://github.com/PowerShellMafia/PowerSploit"
echo "--------------------------------"

svn export https://github.com/PowerShellMafia/PowerSploit/trunk modules/PowerSploit #--force

echo
echo "--------------------------------"
echo "Downloading AD-Recon PS scripts "
echo "GitHub: https://github.com/PyroTek3/PowerShell-AD-Recon"
echo "--------------------------------"

svn export https://github.com/PyroTek3/PowerShell-AD-Recon/trunk modules/ad-recon #--force

echo
echo "--------------------------------"
echo "Downloading Nishang PS scripts "
echo "GitHub: https://github.com/samratashok/nishang"
echo "--------------------------------"

svn export https://github.com/samratashok/nishang/trunk modules/nishang #--force
