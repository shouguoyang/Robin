# Robin

A patch and vulnerability detection tool.

For more details, please see our paper [url](https://dl.acm.org/doi/10.1145/3604608).

# Preparation

1. `pip install -r requirments.txt`.
2. Install IDA Pro 7.x. Then set the path of ida to the variable `ida` in `running_setting.py`. Make sure the IDA python working well.

# Usage


Please check the help instruction by running `python main.py --help`.

```
usage: Patch detection tool. [-h] [--mfi] [--cve_id CVE_ID]
                             [--path_to_vul_bin PATH_TO_VUL_BIN]
                             [--path_to_patch_bin PATH_TO_PATCH_BIN]
                             [--vul_func_name VUL_FUNC_NAME] [--detect]
                             [--target_bin TARGET_BIN]
                             [--target_func_name TARGET_FUNC_NAME]
                             [--debug_mode]

optional arguments:
  -h, --help            show this help message and exit
  --mfi                 generate MFI of Vulnerability. Please specify options
                        of cve_id, path_to_vul_bin, path_to_patch_bin,
                        vul_func_name
  --cve_id CVE_ID       CVE ID
  --path_to_vul_bin PATH_TO_VUL_BIN
                        path to vulnerable binary
  --path_to_patch_bin PATH_TO_PATCH_BIN
                        path to patched binary
  --vul_func_name VUL_FUNC_NAME
                        vulnerable/patched function name
  --detect              detecting patched or vulnerable code within given
                        target bin. Please specify options of cve_id,
                        target_bin, vul_func_name
  --target_bin TARGET_BIN
  --target_func_name TARGET_FUNC_NAME
                        The name of target function which may contains patched
                        or vulnerable code.
  --debug_mode
```

## Offline

### MFI Building


For example:

`python main.py --mfi --cve_id CVE-2015-0288 --path_to_vul_bin binaries/openssl/O0/openssl-1.0.1l --path_to_patch_bin binaries/openssl/O0/openssl-1.0.1m --vul_func_name X509_to_X509_REQ`

## Online Detection

For example:

`python main.py --detect --cve_id CVE-2015-0288 --target_bin binaries/openssl/O0/openssl-1.0.1k --vul_func_name X509_to_X509_REQ`

The output will be:  `Overal Score is: -0.966`

The scoring system ranges from -1 to 1, where values closer to -1 indicate that the detected function exhibits more characteristics similar to vulnerable functions. On the other hand, scores closer to 1 suggest that the detected function displays more similarities with patched functions.

# Dataset
see `./data/cve_all`