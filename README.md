krypton
=======

https://www.hex-rays.com/contests/2012/

Here's the short description, from the documentation:

Krypton is an IDA Plugin that assists one in executing a function from IDB (IDA database) using IDA's powerful Appcall feature
krypton takes xrefs from a given function (say a possible decoder) to find all function calls to it and then parses and finds the parameters used (including prototype, no of arguments, and the arguments themselves) from instructions and uses them to execute the function using Appcall, this is most useful in analyzing a malware binary with encryption

Our comments: Krypton can be very useful if you're often dealing with malware that encrypts its strings or other commonly used data. The source code was clean and the documentation very helpful.
