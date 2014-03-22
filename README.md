Sniffy
======

This is a simple network sniffer that sniffs packets at the Network Layer (IP Layer), parse it and displays the IP Header informations. It also do a hex and ASCII dump of the data sniffed.

The "ip" class has two methods:
[1] extract(): this method extracts the IP header elements and stores them in a list
[2] parse(): used to parse the IP header elements through an sqlite database that contains descriptions of the IP Header elements (e.g: protocol, precedence, ...)
