# Shodan Cheat Sheet

## Filter 

Here are the basic search filters you can use:

* `city`: find devices in a particular city
* `country`: find devices in a particular country
* `geo`: you can pass it coordinates
* `hostname`: find values that match the hostname
* `net`: search based on an IP or /x CIDR
* `os`: search based on operating system
* `port`: find particular ports that are open
* `before/after`: find results within a timeframe

## Examples

Find Apache servers in San Francisco:

	apache city:"San Francisco"

Find Nginx servers in Germany:

	nginx country:"DE"

Find GWS (Google Web Server) servers:

	"Server: gws" hostname:"google"

Find Cisco devices on a particular subnet:

	cisco net:"216.219.143.0/24"
