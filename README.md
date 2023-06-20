These are proofs of concept for four issues in Fortra Globalscape 8.0.x and 8.1.x
versions prior to 8.1.0.16. These will be discussed in detail on the Rapid7
blog, but for now, here are the tools:

* CVE-2023-2989 - authentication bypass via out-of-bounds memory read - a very
  simple proof of concept is in
  [oob-memory-read-poc.rb](/oob-memory-read/oob-memory-read-poc.rb), which
  attempts to exploit the issue by bruteforce
* CVE-2023-2990 - denial of service due to recursive Deflate stream - a super
  interesting exploit for an uninteresting vulnerability, but we developed a
  malicious message that can be found in in
  [recursive.zlib](/quine-zip-dis/recursive.zlib)
* CVE-2023-2991 - remote disclosure of harddrive serial number via a
  trial-extension-request message - a small information disclosure that we
  implement in [request-hdd-serial.rb](/request-hdd-serial/request-hdd-serial.rb)
* A tool that can decrypt a user's password from an administrator session that
  does not use SSL - implemented in [recover-pw.rb](recover-pw/recover-pw.rb)

These tools were all developed by Ron Bowes at Rapid7 as part of a research
project. They are supplied as-is, as proofs of concept, and are definitely not
production-ready.
