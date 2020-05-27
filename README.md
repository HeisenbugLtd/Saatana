![](https://raw.githubusercontent.com/HeisenbugLtd/heisenbugltd.github.io/master/assets/img/saatana/cover.png)

# SPARK/Ada Algorithms Targeting Advanced Network Applications
A cryptographic framework, proven for correctness in SPARK

[![](https://github.com/HeisenbugLtd/Saatana/workflows/Build%20Linux/badge.svg)](https://github.com/HeisenbugLtd/Saatana/actions?query=workflow%3A"Build+Linux")
[![](https://github.com/HeisenbugLtd/Saatana/workflows/Proof%20Linux/badge.svg)](https://github.com/HeisenbugLtd/Saatana/actions?query=workflow%3A"Proof+Linux")

Requires GNAT Community 2020, as we are making use of SPARK's [Relaxed_Initialization](https://docs.adacore.com/spark2014-docs/html/ug/en/source/specification_features.html#aspect-relaxed-initialization-and-attribute-initialized).

Algorithms contained
- [Phelix](https://www.schneier.com/academic/archives/2005/01/phelix.html) - Fast Encryption and Authentication in a Single Cryptographic Primitive

  Doug Whiting, Bruce Schneier, Stefan Lucks, and Frédéric Muller

  ECRYPT Stream Cipher Project Report 2005/027, 2005.

  ABSTRACT: Phelix¹ is a high-speed stream cipher with a built-in MAC functionality. It is efficient in both hardware and software. On current Pentium CPUs, Phelix has a per-packet overhead of less than 900 clocks, plus a per-byte cost well under 8 clocks per byte, comparing very favorably with the best AES (encryption-only) implementations, even for small packets.

  ¹ Pronounced "felix" (rhymes with "helix").
