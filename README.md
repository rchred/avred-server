# avred - Server

Provides an HTTP interface to scan files with the installed AntiVirus software on Windows. 


## Details 

To be used with the AV Reduction [avred](https://github.com/dobin/avred) project. Exposes 2 endpoints, one accepts a (virus) file and runs an AV against it. The other accepts a url, which is then called with chrome to simulate a more realistic download (MOTW, events, Defender magic, ...).

Returns ```200 {"detected": true}``` if file was detected by AV, or ```200 {"detected": false}``` if it wasn't, or ```500 {"exception": 'error'}``` if there was an error. 


## Setup

0. Create a (Windows) VM and install the AV of your choosing (or use pre-installed Defender)
1. install python3,  pip3 & requirements.txt
	- Windows: download python from https://www.python.org/downloads/, include pip in installation, then open powershell: ```pip install -r requirements.txt```
	- Linux: ```sudo apt install python3 python3-pip && pip3 install -r requirements.txt```
2. check config.json
3. put the "virus_dir" (default `c:\temp\`) on the AV exclusion list
4. Disable sample submission on your AV
4. Browser to `localhost:8001/test` to check if it works

