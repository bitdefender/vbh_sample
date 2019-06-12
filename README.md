# Bitdefender introspection PoC for VBH

This project demonstrates protection for three types of exploits:

- SMEP/SMAP disabling
- vDSO modifications
- runc overwrite

## SMEP/SMAP disable

### Overview

- SMEP: If set, execution of code in a higher ring generates a fault.
- SMAP: If set, access of data in a higher ring generates a fault.
  A malicious program may disable SMAP in order to access data at linear
  addresses that are accessible in user-mode. Or it may disable SMEP in order to
  fetch instructions from linear addresses that accessible to user-mode.

### Our approach

To avoid these types of malicious actions we have set the mask such that every
attempt to modify the CR4 register will cause a VMEXIT.

This has been tested against
[CVE-2017-7308](https://access.redhat.com/security/cve/cve-2017-7308)
([PoC](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-7308/poc.c)).

## vDSO modifications

### Overview

A race condition in `mm/gup.c` in the Linux kernel `2.x` through `4.8.3`, allows
local users to gain privileges by leveraging the incorrect handling of a
copy-on-write (COW) feature to write to a read-only memory mapping.  This has
been exploited in the wild in October 2016 (Dirty COW).

### Our approach

We removed write permissions to the EPT page in which the vDSO resides to stop
vDSO modifications.

This has been tested against
[CVE-2016-5195](https://access.redhat.com/security/cve/cve-2016-5195)
([PoC](https://github.com/clearcontainers/cc-dirtycow-demo)).

## runc modifications

### Overview

runc through `1.0-rc6`, as used in Docker before `18.09.2`, and also in other
products, allows attackers to overwrite the host runc binary and consequently
obtain host root access.

### Our approach

We detoured the function for file opening and denied access for each attempt to
open runc for writing to stop this exploit.

This has been tested against
[CVE-2019-5736](https://access.redhat.com/security/cve/cve-2019-5736)
([PoC](https://github.com/Frichetten/CVE-2019-5736-PoC)).

## Usage

```
$ git clone https://github.com/bitdefender/vbh_sample.git
$ cd vbh_samble
$ git submodule init && git submodule update
$ make
$ insmod vbh/sources/vmx-switch.ko switch_vmx_on_load=1
$ insmod hvi/hvi.ko
```

This will build and install the `hvi` and `vbh` modules.
