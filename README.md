Requirements

    Python 2.7.x
    BeautifulSoup4==4.3.2
    py2-ipaddress==3.4.1

with pip installed, you can install required packages

    pip install -r requirements.txt

Usage

usage: weakscan.py [options]

A web vulnerability scanner by whynot

optional arguments:
  -h, --help        show this help message and exit
  --host host       scan a simple host
  -f weakfile       load the host from weakfile
  -d weakdirectory  load all *.txt from weakdirectory
  --network CIDR    scan CIDR host should be int between 24 and 31
  -v                show program's version number and exit

If you use this program, please do not used for illegal purposes

1. Scan a single host www.target.com

python BBScan.py  --host www.target.com --browser

2. Scan www.target.com and all the other ips in www.target.com/28 networks

python BBScan.py  --host www.target.com --network 28

3. Load some targets from file

python BBScan.py -f wandoujia.com.txt

4. Load all targets from Directory

python BBScan.py -d targets/

