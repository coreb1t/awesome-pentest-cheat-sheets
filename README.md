# Awesome Pentest Cheat Sheets [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

Collection of cheat sheets useful for pentesting

### Contribution
Your contributions and suggestions are heartily welcome. Please check the [Contributing Guidelines](.github/CONTRIBUTING.md) for more details.


## Security Talks and Videos

* [InfoCon - Hacking Conference Archive](https://infocon.org/cons/)
* [Curated list of Security Talks and Videos](https://github.com/PaulSec/awesome-sec-talks)

## General

* [Docker Cheat Sheet](https://github.com/wsargent/docker-cheat-sheet)
* [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
* [OSX Command Line Cheat Sheet](https://github.com/herrbischoff/awesome-osx-command-line)
* [PowerShell Cheat Sheet](https://pen-testing.sans.org/blog/2016/05/25/sans-powershell-cheat-sheet) - SANS PowerShell Cheat Sheet from SEC560 Course [(PDF version)](docs/PowerShellCheatSheet_v41.pdf)
* [Regexp Security Cheat Sheet](https://github.com/attackercan/regexp-security-cheatsheet)
* [Security Cheat Sheets](https://github.com/jshaw87/Cheatsheets) - A collection of security cheat sheets
* [Unix / Linux Cheat Sheet](http://cheatsheetworld.com/programming/unix-linux-cheat-sheet/)

## Discovery

* [Google Dorks](https://www.exploit-db.com/google-hacking-database) - Google Dorks Hacking Database (Exploit-DB)
* [Shodan](docs/shodan.md) - Shodan is a search engine for finding specific devices, and device types, that exist online

## Enumeration
* [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) - Python script to enumerate target system

## Exploitation
* [Empire Cheat Sheet](https://github.com/HarmJ0y/CheatSheets/blob/master/Empire.pdf) - [Empire](http://www.powershellempire.com) is a PowerShell and Python post-exploitation framework 
* [Exploit Development Cheat Sheet](docs/pentest-exploit-dev-cheatsheet.jpg) - [@ovid](https://twitter.com/ovid)'s exploit development in one picture
* [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet) - A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities
* [Local File Inclution (LFI) Cheat Sheet #1](https://highon.coffee/blog/lfi-cheat-sheet/) - Arr0way's LFI Cheat Sheet
* [Local File Inclution (LFI) Cheat Sheet #2](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/) - Aptive's LFI Cheat Sheet
* [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/) - The ultimate guide to the Metasploit Framework
* [Metasploit Cheat Sheet](https://www.tunnelsup.com/metasploit-cheat-sheet/) - A quick reference guide [(PNG version)](docs/Metasploit-CheatSheet.png)[(PDF version)](docs/Metasploit-CheatSheet.pdf)
* [PowerSploit Cheat Sheet](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerSploit.pdf) - [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) is a powershell post-exploitation framework
* [PowerView 2.0 Tricks](https://gist.github.com/HarmJ0y/3328d954607d71362e3c)
* [PowerView 3.0 Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
* [PHP htaccess Injection Cheat Sheet](https://github.com/sektioneins/pcc/wiki/PHP-htaccess-injection-cheat-sheet) - htaccess Injection Cheat Sheet by PHP Secure Configuration Checker
* [Reverse Shell Cheat Sheet #1](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) - Pentestmonkey Reverse Shell Cheat Sheet
* [Reverse Shell Cheat Sheet #2](https://highon.coffee/blog/reverse-shell-cheat-sheet) - Arr0way's  Reverse Shell Cheat Sheet
* [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet) - Netsparker's SQL Injection Cheat Sheet
* [SQLite3 Injection Cheat Sheet](http://atta.cked.me/home/sqlite3injectioncheatsheet)

## Privilege Escalation

### Learn Privilege Escalation

* [Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop) - The Privilege Escalation Workshop covers all known (at the time) attack vectors of local user privilege escalation on both Linux and Windows operating systems and includes slides, videos, test VMs.
<img src="https://pbs.twimg.com/media/DAZsE2VUQAA_bpZ.jpg">

### Linux Privilege Escalation

* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) - Linux Privilege Escalation by [@g0tmi1k](https://twitter.com/g0tmi1k)
* [linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester) - Linux privilege escalation auditing tool written in bash (updated)
* [Linux_Exploit_Suggester.pl](https://github.com/PenturaLabs/Linux_Exploit_Suggester) - Linux Exploit Suggester written in Perl (last update 3 years ago)
* [Linux_Exploit_Suggester.pl v2](https://github.com/jondonas/linux-exploit-suggester-2) - Next-generation exploit suggester based on Linux_Exploit_Suggester (updated)
* [Linux Soft Exploit Suggester](https://github.com/belane/linux-soft-exploit-suggester) - linux-soft-exploit-suggester finds exploits for all vulnerable software in a system helping with the privilege escalation. It focuses on software packages instead of Kernel vulnerabilities
* [checksec.sh](https://github.com/slimm609/checksec.sh) - bash script to check the properties of executables (like PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)
* [linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) - This script is intended to be executed locally on a Linux box to enumerate basic system info and search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text passwords and applicable exploits (@SecuritySift)
* [LinEnum](https://github.com/rebootuser/LinEnum) - This tool is great at running through a heap of things you should check on a Linux system in the post exploit process. This include file permissions, cron jobs if visible, weak credentials etc.(@Rebootuser)
* [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) - LinPEAS - Linux Privilege Escalation Awesome Script. Check the Local Linux Privilege Escalation checklist from [book.hacktricks.xyz](https://book.hacktricks.xyz)



### Windows Privilege Escalation

* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) - Excellent powershell script for checking of common Windows privilege escalation vectors. Written by [harmj0y](https://twitter.com/harmj0y) [(direct link)](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)
* [PowerUp Cheat Sheet](https://github.com/HarmJ0y/CheatSheets/blob/master/PowerUp.pdf)
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Tool for detection of missing security patches on the windows operating system and mapping with the public available exploits
* [Sherlock](https://github.com/rasta-mouse/Sherlock) - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities
* [Watson](https://github.com/rasta-mouse/Watson) - Enumerate missing KBs and suggest exploits for useful Privilege Escalation vulnerabilities
* [Precompiled Windows Exploits](https://github.com/abatchy17/WindowsExploits) - Collection of precompiled Windows exploits
* [Metasploit Modules](https://github.com/rapid7/metasploit-framework)
  * post/multi/recon/local_exploit_suggester - suggests local meterpreter exploits that can be used
  * post/windows/gather/enum_patches - helps to identify any missing patches


## Tools

* [Nmap Cheat Sheet](docs/nmap.md)
* [SQLmap Cheat Sheet](docs/sqlmap-cheatsheet-1.0-SDB.pdf)
* [SQLmap Tamper Scripts](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423) - SQLmal Tamper Scripts General/MSSQL/MySQL
* [VIM Cheatsheet](https://i.imgur.com/YLInLlY.png)
* [Wireshark Display Filters](docs/Wireshark_Display_Filters.pdf) - Filters for the best sniffing tool

# Tools Online
* [XSS'OR Encoder/Decoder](http://xssor.io/#ende) - Online Decoder/Encoder for testing purposes (@evilcos)
* [WebGun](https://brutelogic.com.br/webgun/) - WebGun, XSS Payload Creator (@brutelogic)
* [Hackvertor](https://hackvertor.co.uk) - Tool to convert various encodings and generate attack vectors (@garethheyes)
* [JSFiddle](https://jsfiddle.net) - Test and share XSS payloads, [Example PoC](https://jsfiddle.net/xqjpsh65/)

## Payloads

### Genaral
* [Fuzzdb](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application testing
Polyglot Challenge with submitted solutions
* [SecList](https://github.com/danielmiessler/SecLists) - A collection of multiple types of lists used during security assessments. List types include usernames, passwords, URLs, sensitive data grep strings, fuzzing payloads, and many more

### XSS
* [XSS Polyglot Payloads #1](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot) - Unleashing an Ultimate XSS Polyglot list by 0xsobky
* [XSS Polyglot Payloads #2](http://polyglot.innerht.ml/) - [@filedescriptor](https://twitter.com/filedescriptor)'s XSS 
* [Browser's-XSS-Filter-Bypass-Cheat-Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)- Excellent List of working XSS bapasses running on the latest version of Chrome / Safari, IE 11 / Edge created by Masato Kinugawa

## Write-Ups

* [Bug Bounty Reference](https://github.com/ngalongc/bug-bounty-reference) - huge list of bug bounty write-up that is categorized by the bug type (SQLi, XSS, IDOR, etc.)
* [Write-Ups for CTF challenges](https://ctftime.org/writeups)
* [Facebook Bug Bounties](https://www.facebook.com/notes/phwd/facebook-bug-bounties/707217202701640) - Categorized Facebook Bug Bounties write-ups


## Learning Platforms

### Online
* [Hack The Box :: Penetration Testing Labs](https://www.hackthebox.eu)
* [OWASP Vulnerable Web Applications Directory Project (Online)](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=On-Line_apps) - List of online available vulnerable applications for learning purposes
* [Pentestit labs](https://lab.pentestit.ru) - Hands-on Pentesting Labs (OSCP style)
* [Root-me.org](https://www.root-me.org) - Hundreds of challenges are available to train yourself in different and not simulated environments
* [Vulnhub.com](https://www.vulnhub.com) - Vulnerable By Design VMs for practical 'hands-on' experience in digital security

### Off-Line
* [Damn Vulnerable Xebia Training Environment](https://github.com/davevs/dvxte) - Docker Container including several vurnerable web applications (DVWA,DVWServices, DVWSockets, WebGoat, Juiceshop, Railsgoat, django.NV, Buggy Bank, Mutilidae II and more)
* [OWASP Vulnerable Web Applications Directory Project (Offline)](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=Off-Line_apps) - List of offline available vulnerable applications for learning purposes

## Wireless Hacking

### Tools

* [wifite2](https://github.com/coreb1t/wifite2) - Full authomated WiFi security testing script 

## Defence Topics

* [Docker Security Cheat Sheet](https://container-solutions.com/content/uploads/2015/06/15.06.15_DockerCheatSheet_A2.pdf) - The following tips should help you to secure a container based system [(PDF version)](docs/DockerCheatSheet.pdf)
* [Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening) - A curated list of awesome Security Hardening techniques for Windows

## Programming

* [JavaScript Cheat Sheet](https://github.com/coodict/javascript-in-one-pic) - Learn javascript in one picture [(Online version)](https://git.io/Js-pic) [(PNG version)](docs/js-in-one-pic.png) 
* [Python Cheat Sheet #1](https://github.com/siyuanzhao/python3-in-one-pic) - Learn python3 in one picture [(PNG version)](docs/python-3-in-one-pic.png)
* [Python Cheat Sheet #2 ](https://github.com/coodict/python3-in-one-pic) - Learn python3 in one picture [(Online version)](https://git.io/Coo-py3) [(PNG version)](docs/py3-in-one-pic.png)
* [Python Snippets Cheat Sheet](docs/python-snippets.md) - List of helpful re-usable code snippets in Python 


