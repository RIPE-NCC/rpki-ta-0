RPKI - trust anchor software
============================

License
-------

Copyright (c) 2017-2022 RIPE NCC
All rights reserved.

This software, including all its separate source codes, is licensed under the
terms of the BSD 3-Clause License. If a copy of the license was not distributed
to you, you can obtain one at
https://github.com/RIPE-NCC/rpki-ta-0/blob/main/LICENSE.txt.

Changelog
---------

### v0.5.1
  * Publish releases on GitHub

### v0.5.0
  * rpki-commons 1.39.1
  * Updated gradle plugins (to fix build warnings)
  * Updated gradle version in gradle wrapper
  * Fixed deployment

### v0.4.0
  * **hotfix** fix bug in manifest this/nextUpdate calculation
  * Use the same timestamp for signing all the objects (TA certificate, MFT, CRL)
  * Publish docker image to GHCR insetead of dockerhub
  * Updated github actions
  * Add feature to revoke objects that TA0 knows off, but are not requested
    (e.g. leftover files on manifest).
  * Publish docker image `ghcr.io/ripe-ncc/rpki-ta-0`
  * Use rpki-commons 1.35
  * Compile with JDK 11

### 0.3.5:
  * Removed explicit license from all files.
  * Save backup of trust anchor state when saving
  * Print sha256 when loading or storing trust anchor state.
  * Build with gradle
  * Switch `prepdev` environment back to software keys.
  * Switch to `junit-jupiter` and `assertj` in tests.
  * Add github actions

### 0.3.4:
  * Add lombok
  * Replace log4j by slf4j/logback.

### 0.3.2:
  * Release installed on HSM machine on 2022-1-18

### 0.3:

  * Update RPKI commons to a recent version
  * Make storage directory configurable

### 0.2:

  * Use RPKI commons version that uses the correct encoding in manifest and has
    Xstream fixes
  * `--force-new-ta-certificate` option to override signing when there is a
    difference between request and embedded config and TA certificate needs to
    change.

### 0.1:

  * Initial release
