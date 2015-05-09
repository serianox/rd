rd
==
**rd** is a proof-of-concept of sandboxing apps that performs root detection.

Root detection is the cargo-cult of Android security. Everyone does it, nobody knows why.

How does it work?
-----------------
I use `ptrace` to call `dlopen` on the remote process. The loaded library has a constructor that replaces the code of `access` with its own.

If you look at the Android source code, `File.exists` calls `access`. If an app tries to check the presence of `su`, I simply have to emulate its absence.

---
## FAQ ##

* Does it…?

RTFC

---
## LICENSE ##
It is released under the WTFPL, so you are free to show that root detection is useless.
