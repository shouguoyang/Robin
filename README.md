# Robin

A patch and vulnerability detection tool.

# Preparation

1. `pip install -r requirments.txt`.
2. Install IDA Pro 7.x.

# Usage

## Offline

### CVE PoC inputs and Signatures Generation

see function `PoC_Sig_Gen()` in `patch_test.py`

#### Patch Positioning
```
>>> from patch_location.PatchLocation import diff_main
>>> check_addr, guard_addr = diff_main("binaries/openssl/O0/openssl-1.0.1l", "binaries/openssl/O0/openssl-1.0.1m", "X509_to_X509_REQ", True, ida = "/home/angr/idapro-7.5/idat")
>>> print(hex(check_addr), hex(guard_addr))
0x8164b2d 0x8164b95
```

#### PoC Generation
```
>>> from patch_detection import input_gen
>>> input_gen("CVE-2015-0288", "binaries/openssl/O0/openssl-1.0.1m", func_name = "X509_to_X509_REQ", check_addr="0x8164b2d", patch_addr="0x8164b95", force_generation=False)
```
#### CVE Signature Generation

```
>>> from patch_detection import generate_cve_sig
>>> generate_cve_sig(cveid='CVE-2015-0288', vul_bin="binaries/openssl/O0/openssl-1.0.1l", patched_bin='binaries/openssl/O0/openssl-1.0.1m', func_name="X509_to_X509_REQ")
True
```

## Online Detection

see function `patch_test()` in `patch_test.py`

```angular2
INFO    | 2021-03-02 14:22:16,301 | patch_detection | [*] start null pointer dereference detection for X509_to_X509_REQ of CVE-2015-0288 in /home/angr/Soter/binaries/openssl/O0/openssl-1.0.1k
INFO    | 2021-03-02 14:22:16,468 | patch_detection | [*] preparing memory layout for detection >>>
INFO    | 2021-03-02 14:22:17,318 | preparation | [*] calling convention detecting...
INFO    | 2021-03-02 14:22:17,553 | patch_detection | [+] start detection with se in function X509_to_X509_REQ of /home/angr/Soter/binaries/openssl/O0/openssl-1.0.1k
```
<span style="color: red; ">` WARNING | 2021-03-02 14:22:22,627 | RuntimeRecorder | Null Pointer Dereference founded at instruction 0x814c1b2: CsInsn 0x814c1b2 [8b400c]: mov eax, dword ptr [eax + 0xc]` </span>



# Dataset
see `./data/cve_all`