# Bitdefender introspection PoC for VBH

This module prevents malicious code from disabling SMAP/SMEP bits and denies any malicious writes    
into vDSO using the API provided by Intel's vbh module.

## Usage:

```
$ git clone https://github.com/bitdefender/vbh_sample.git
$ cd vbh_samble
$ git submodule init && git submodule update
$ make
$ insmod vbh/sources/vmx-switch.ko switch_vmx_on_load=1
$ insmod hvi/hvi.ko
```

This will build and install hvi and vbh modules.
