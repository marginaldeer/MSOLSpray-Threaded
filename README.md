# MSOLSpray-Threaded
This is a combination of MartinIngesen's MSOLSpray (https://github.com/MartinIngesen/MSOLSpray) and byt3bl33d3r's threaded port (https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f) coincidently this is all original work of DaftHack(https://github.com/dafthack/MSOLSpray). I barely modified much of anything so all credit goes to them. 

Features I needed and added:

* Outfile - Writes to enumed_users.lst by default but can be specified via -o or --outfile
* Domain - made it so the domain can be specified as a domain arguement with -d or --domain
* Foxprox - added the --url paramenter to support proxies such as AWS's foxprox

Various other improvements to usability.

# Running
```
pip install aiohttp[speedups]
chmod +x ./msol_spray.py
./msol_spray -u FILE -p Testing123! -d test.com --outfile test_users.txt 
```

This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
