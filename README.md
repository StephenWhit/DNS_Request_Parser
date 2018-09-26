Stephen Whitcomb 811330368

CSCI 4760 Networks

Homework 2

Description:
This is a simple DNS response parser. It takes in a hex string and breaks it up
and displays it in a similar fashion as dig(1)

Run the code by typing:
$ python3 dns_parse.py filename

The test files should be located in the same directory as the dns_parse.py

Caveat: this parser will only interpret CNAME, NS, and A type Responses. It will not work properly with SOA, MX, TXT etc.