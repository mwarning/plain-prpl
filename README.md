plain-prpl
==========

Plain is a protocol plugin for the Pidgin instant messenger.

The protocol is very simplistic. You can add buddies via an address
to send and receive plain text messages via UDP packets.
To provide secure communications you can use
the [OTR Plugin](https://otr.cypherpunks.ca/) on top of Plain.

The address for each buddy can be an IP address or a domain name address.
But these is somewhat limiting. IP addresses may change daily and depend
on the location and domain names are not easy to register. To solve this,
Plain supports to resolve an arbitrary adddress string by calling an external program.

The focus at this point is on [KadNode](https://github.com/mwarning/KadNode).
It is a daemon employing a Distributed Hash Table (Mainline DHT) that
connects to networks that are usually used for trackerless Torrents.
KadNode can leverage these networks for much broader uses as
domain name announcements and resolution.

Plain will try to make it trivial to use KadNode
and without making it a necessary dependency.

The project is currently in a alpha stage.
