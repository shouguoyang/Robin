from patch_detection import *


################ Tests ##################################
from patch_localization.patch_localization import diff_main
from patch_detection import generate_cve_sig

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
    # entry = "CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1k,X509_to_X509_REQ"
    entry = "CVE-2014-0160,/home/angr/PatchDiff/binaries/openssl/O0/openssl-1.0.1a,dtls1_process_heartbeat"
    splited = entry.strip().split(',')
    target_bin = os.path.join(rootdir, splited[1]) # target version
    func_name = splited[2]
    CVEID = splited[0] # important!
    func_to_detect = splited[-1]
    v = PatchDetection(CVE=CVEID, target_bin=target_bin, vul_func_name=func_name,
                       force_new=False, to_detect_func_name=func_to_detect)
    print("Overal Score is: {:.3f}".format(v))

if __name__ == '__main__':
    # PoC_gen()
    patch_test()
