Vds 0.9.9
=============

What is Vds?
--------------

[Vds] is Based on Bitcoin's code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. Technical details are available

This software is the Vds client. It downloads and stores the entire history
of Vds transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

Security Warnings
-----------------

See important security warnings in
[doc/security-warnings.md](doc/security-warnings.md).

**Vds is unfinished and highly experimental.** Use at your own risk.

**This OpenSource version is for trading only.** 

Deprecation Policy
------------------

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height and can be explicitly disabled.

Where do I begin?
-----------------
We have a guide for joining the main Vds network:

Participation in the Vds project is subject to a
[Code of Conduct](code_of_conduct.md).

Building
--------

Build Vds along with most dependencies from source by running
./vcutil/build.sh. Currently only Linux is officially supported.

License
-------

For license information see the file [COPYING](COPYING).
