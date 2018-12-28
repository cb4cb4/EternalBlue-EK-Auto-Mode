# EBEK---EternalBlue-EK

EternalBlue
EternalSynergy
EternalRomance
EternalChampion

:: CVE List ::
CVE-2017-0143
CVE-2017-0144
CVE-2017-0145
CVE-2017-0146
CVE-2017-0147
CVE-2017-0148

:: Tested On ::
- Windows XP SP3 x86
- Windows XP SP2 x64
- Windows 7 SP1 x86
- Windows 7 SP1 x64
- Windows 8.1 x86
- Windows 8.1 x64
- Windows 10 Pro Build 10240 x64

- Windows Server 2000 SP4 x86
- Windows Server 2003 SP2 x86
- Windows Server 2003 R2 SP2 x64
- Windows Server 2008 SP1 x86
- Windows Server 2008 SP1 x64
- Windows Server 2008 R2 SP1 x64
- Windows Server 2012 R2 x64
- Windows Server 2016 x64

:: Payload Options ::
- Powershell Reverse Shell
- Download & Execute
- VNC Injector
- Add Remote Desktop User


#######################
#  EBEK REQUIREMENTS  #
#######################

* Python 2.7

* Pip

* Build-Essential

* Libssl-dev

* Libffi-dev

* Python-dev

* Impacket

* Pycrypto

* Clint

* Pyasn1


###############################
#  Debian Based OS - Install  #
###############################

apt-get install python python-pip build-essential libssl-dev libffi-dev python-dev

pip install impacket pycrypto clint socket ipaddress pyasn1


###############################
#  CentOS Based OS - Install  # 
###############################

yum install python python-pip build-essential libssl-dev libffi-dev python-dev

pip install impacket pycrypto clint socket ipaddress pyasn1


################################
#  Windows Based OS - Install  #
################################

pip install impacket pycrypto clint socket ipaddress pyasn1


#####################
#  Auto-Mode Usage  #
#####################

python auto_mode.py 192.0.0.0/8

Any Valid CIDR Range may be supplied.
https://www.ripe.net/about-us/press-centre/IPv4CIDRChart_2015.pdf

Example:
192.168.1.0/24 = 256 IP's
192.168.0.0/16 = 64K IP's
192.0.0.0/8    = 16M IP's
0.0.0.0/0      = 4096M IP's

- EXE or DLL Supported.
- All executions with SYSTEM privileges.




