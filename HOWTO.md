## Introduction

ClueVPN is not designed to compete with typical VPN protocols such as OpenVPN
or IPSec.  These protocols establish point-to-point connections with an
endpoint, and do so very well.

ClueVPN is designed as a mesh routing VPN, where there are many peers in a
network, all communicating with each other.  Using usual methods, all
communication goes through a central server, which is a bottleneck and a
single point of failure.  With ClueVPN, each peer communicates directly with
each other peer.

If you want to set up a VPN between two hosts, don't use ClueVPN - I recommend
OpenVPN or vtun for that.  Even with three hosts, you can establish mesh
routing by running separate connections.  But running multiple openvpn or vtun
VPNs for mesh routing quickly gets unmanagable.

For a mesh routing network to directly send data between peers, each peer
needs to know about every other peer.  With ClueVPN, this is accomplished with
a list of peers called the Bootstrap Node List (BNL).

The BNL contains data for each node in the network, including its "real" IP
address(es) and the virtual subnet allocated to it.

ClueVPN peers have the ability to automatically discover updated BNLs from
peers, so adding a new node is as simple as updating the BNL on a single peer.
There's no need to change configuration on every node to modify the network
structure or routes.  Each BNL is timestamped so each node knows when a BNL is
newer.

Since the BNL can be automatically discovered from other nodes, protection is
built in to make sure that no "rogue" node introduces an incorrect BNL.  The
BNL is signed by the creator, and each node verifies the signature.  BNLs are
signed with DSA keys, which must be generated for the ClueVPN network to
properly function.

ClueVPN data is sent over UDP.  It is encrypted (with an included sequence
number and hash) and optionally compressed, then sent to the destination node.
The encryption key as well as the encryption algorithm, compression algorithm
(if any), and compression level, are kept for each pair of nodes.  For
example, in a 3-node network (nodes A, B, and C), nodes A<->B share
encryption/comression parameters, nodes B<->C share parameters, and nodes
A<-C share parameters.  Each node stores its parameters for communicating with
each other node.

If two nodes have not agreed on encryption/compression parameters, they are
automatically established via a process called negotiation.  Negotiation
occurs over TCP.  One node makes a connection to the other node using SSL.
Both nodes verify that the other node's certificate was signed by the VPN CA,
and gets the identity of the node from the certificate's Common Name.  They
exchange supported algorithms and preferences, and both generate a random
encryption key.  From this information, an encryption key for both to use as
well as the algorithms is determined.  These are stored, so if the VPN daemon
restarts, it doesn't need to renegotiate.

BNLs can be shared via two methods - pushes and pulls.  Periodically (every
few minutes approximately - it varies depending on how many "spare"
connections there are), each node asks every other node if it has an updated
BNL.  If the remote node does have an updated BNL, it is transmitted, the
signature verified, and the daemon refreshed to use the new BNL.  If BNL pulls
are too slow, BNL pushes can also be used.  A BNL push must be manually
initiated by sending SIGUSR1 to a running ClueVPN daemon.  This both causes
the BNL to be reloaded from the disk and the BNL to be pushed to every other
node (if the timestamp is newer).

## Getting Started

First comile the daemon and install it (make && sudo make install).  Example
configuration files will be placed in /etc/cluevpn.

You will need to decide on a subnet to use for the VPN as a whole, and
sections of that subnet to assign to each node.  For example, you can choose
to use the subnet 10.1.0.0/16 for the entire VPN, and assign each node a /24.

On your first node, you should create the DSA keys for signing BNLs and set up
the CA for node certificates.

To create the DSA keys, run the command: ./makedsakeys.sh.  Copy the resulting
files (bnlkey-*.pem) to /etc/cluevpn.

Then, cd to the "example-ca" directory, and set up a CA, and a certificate/key
for each node.  Read the README file in that directory for more information.
Copy the CA certificate and the certificate and key files for this node to
/etc/cluevpn.

You'll need to create a configuration file.  Open up the file
/etc/cluevpn/cluevpn.conf, and create the following skeleton configuration:

```
name=testnode.example.com
devname=cluevpn
cert=/etc/cluevpn/testnode.example.com-cluevpn.cert
privkey=/etc/cluevpn/testnode.example.com-cluevpn.key
cacert=/etc/cluevpn/ca-cert.pem
port=3406
bnlpubkey=/etc/cluevpn/bnlkey-pub.pem
bnlprivkey=/etc/cluevpn/bnlkey-priv.pem
upcmd=ifconfig $TUNDEV 10.1.0.1 netmask 255.255.0.0 up
```

Replace testnode.example.com with the name of this node, and replace 10.1.0.1
with the VPN address of this node, and replace 255.255.0.0 with the netmask of
the entire VPN subnet.  If the filenames for any of the files are incorrect,
fix those as well.

After you create the configuration file, you'll need to create the BNL - a
list of each node in the network.  You do this using a program called
`bnlutil`.

To create a new BNL, execute the command:

    bnlutil new

That will create a new BNL and place it in the default location -
`/etc/cluevpn/bnl.bnl`

To add a host, do:

    $ bnlutil add testnode.example.com IPv4=1.2.3.4 Port=3406 Subnet=10.1.0.0/24

Replace testnode.example.com with the name of the node, 1.2.3.4 with the
*external* IP of the node, and 10.1.0.0/24 with the internal subnet assigned
to the node.

There are a few more options - just type `bnlutil` without any arguments to see
the full usage information.

Add each node to the BNL that will be part of the network.

After everything above is done, you should be ready to start the daemon on the
first node.  Just type `cluevpn` and it will start, go into the background,
and log to syslog.  Check syslog for any errors or if it doesn't start.

Once the first node is up and running, adding more nodes is easy.  Just add a
new entry to the BNL (if you haven't already), create a certificate and key
for the new host, create a configuration file similar to the above (but
without the bnlprivkey), and copy the new BNL, the BNL public key, and the CA
certificate.

See the README file for more information.