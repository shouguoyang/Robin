from patch_detection import *


################ Tests ##################################
from patch_localization.patch_localization import diff_main
from patch_detection import generate_cve_sig
from utils import LOG_LEVEL

# Patch Localization & PoC Input Generation & CVE Signature Generation
# PoC Generation
def PoC_gen():
    from MFI_operation.PoC_generation import GeneratePoC
    cve_info = \
'CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1l,binaries/openssl/O0/openssl-1.0.1m,X509_to_X509_REQ'
    cveid, vul_bin, patched_bin, func_name = cve_info.split(",")
    gp = GeneratePoC(cveid, vul_bin, patched_bin, func_name)
    gp.run(new_poc=True)



# patch test
def patch_test():
    set_logger_level(logging.DEBUG)
    entry = "CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1k,X509_to_X509_REQ"
    splited = entry.strip().split(',')
    target_bin = os.path.join(rootdir, splited[1]) # target version
    func_name = splited[2]
    CVEID = splited[0] # important!
    func_to_detect = splited[-1]
    v = PatchDetection(CVE=CVEID, target_bin=target_bin, vul_func_name=func_name,
                       force_new=True, to_detect_func_name=func_to_detect)
    print("Overal Score is: {:.3f}".format(v))

if __name__ == '__main__':
    from  argparse import ArgumentParser

    ap = ArgumentParser('Patch detection tool.')

    ap.add_argument('--mfi', action='store_true', default=False, help='generate MFI of Vulnerability. Please specify options of cve_id, path_to_vul_bin, path_to_patch_bin, vul_func_name')

    ap.add_argument('--cve_id', help='CVE ID')
    ap.add_argument('--path_to_vul_bin', help= 'path to vulnerable binary')
    ap.add_argument('--path_to_patch_bin', help= 'path to patched binary')
    ap.add_argument('--vul_func_name', help= 'vulnerable/patched function name')

    ap.add_argument('--detect', action='store_true', default=False, help='detecting patched or vulnerable code within given target bin. Please specify options of cve_id, target_bin, vul_func_name')
    ap.add_argument('--target_bin')
    ap.add_argument('--target_func_name', help="The name of target function which may contains patched or vulnerable code.")

    ap.add_argument('--debug_mode', action='store_true', default=False)

    args = ap.parse_args()

    if args.debug_mode:
        LOG_LEVEL = logging.DEBUG

    if args.mfi:

        if args.cve_id and args.path_to_vul_bin and args.path_to_patch_bin and args.vul_func_name:
            from MFI_operation.PoC_generation import GeneratePoC
            gp = GeneratePoC(args.cve_id, args.path_to_vul_bin, args.path_to_patch_bin, args.vul_func_name)
            gp.run(new_poc=True)
        else:
            ap.print_help()
    elif args.detect:

        if args.cve_id and args.target_bin and args.vul_func_name:
            v = PatchDetection(CVE=args.cve_id, target_bin=args.target_bin, vul_func_name=args.vul_func_name,
                       force_new=True, to_detect_func_name=args.vul_func_name)
            print("Overal Score is: {:.3f}".format(v))
        else:
            ap.print_help()
    else:
        ap.print_usage()



'''
usage examples:

1. MFI generation

    python main.py --mfi --cve_id CVE-2015-0288 --path_to_vul_bin binaries/openssl/O0/openssl-1.0.1l --path_to_patch_bin binaries/openssl/O0/openssl-1.0.1m --vul_func_name X509_to_X509_REQ

2. patch detection

    python main.py --detect --cve_id CVE-2015-0288 --target_bin binaries/openssl/O0/openssl-1.0.1k --vul_func_name X509_to_X509_REQ
'''