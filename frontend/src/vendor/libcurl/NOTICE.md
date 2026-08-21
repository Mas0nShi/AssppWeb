# Vendored libcurl.js

This directory contains a locally built copy of `libcurl.js` 0.7.4 from
upstream commit `a641cdd857356db6b8ed46c5341cc8f85c4190ba`:

https://github.com/ading2210/libcurl.js/tree/a641cdd857356db6b8ed46c5341cc8f85c4190ba

The only trust-store change is the addition of Apple's official Apple Root CA,
downloaded from:

https://www.apple.com/appleca/AppleIncRootCertificate.cer

The certificate's pinned SHA-256 fingerprint is:

`B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24`

TLS peer and hostname verification remain enabled. `source.patch` contains the
complete source and build-script changes used to create `libcurl_full.mjs` with
Emscripten 3.1.6. The vendored module's SHA-256 digest is:

`af8d667f752cf5f536d136030ea328feb6e18479f074eb9275121d0403a00012`

`libcurl.js` is licensed under LGPL-3.0-or-later; see `LICENSE`.
