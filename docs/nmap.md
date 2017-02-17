# Nmap Cheat Sheet

## DNS Brute Force

    nmap -p 80 --script dns-brute <host>

## Find virtual hosts on an IP address 

    nmap -p 80 --script hostmap-bfk <host>

## Traceroute Geolocation

    nmap -p 80 --traceroute --script traceroute-geolocation.nse  <host>
    
## HTTP Scripts

 + ### HTTP Enum - web path brute force

        nmap -p 80 --script http-enum <host>

 + ### HTTP Title
 
        nmap -p 80 -sV --script http-title  <ip range>
