# Chiron
Chiron is an IPv6 Security Assessment Framework, written in Python and employing Scapy. 
It is comprised of the following modules:
    • IPv6 Scanner
    • IPv6 Local Link
    • IPv4-to-IPv6 Proxy
    • IPv6 Attack Module
    • IPv6 Proxy.
All the above modules are supported by a common library that allows the creation of completely arbitrary IPv6 header chains, fragmented or not.

Suggested host OS: Linux (*BSD may also work).  

Chiron incorporates its own IPv6 sniffer. It doesn't use OS stack.

The main advantage of the tool, in comparison with others, is that it allows you to easily craft arbitrary IPv6 headers chain by using various types of IPv6 Extension Headers. This option can be used for example:
    • To evade IDS/IPS devices, firewalls, or other security devices.
    • To fuzz IPv6-capable devices regarding the handling of IPv6 Extension Headers.
    
To run Chiron, you need Scapy, and of course, Python. 
You also need the following python module: python-netaddr
