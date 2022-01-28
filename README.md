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

### 0.35-SNAPSHOT:
  * Removed explicit license from all files.
  * Save backup of trust anchor state when saving
  * Print sha256 when loading or storing trust anchor state.
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
