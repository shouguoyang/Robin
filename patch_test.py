from patch_detection import *


################ Tests ##################################
from patch_location.PatchLocation import diff_main
from patch_detection import generate_cve_sig

# Patch Positioning & PoC Input Generation & CVE Signature Generation
def PoC_Sig_Gen():
    cvestr = \
            "CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1l,binaries/openssl/O0/openssl-1.0.1m,X509_to_X509_REQ"
    set_logger_level(logging.INFO)
    e = cvestr.split(",")
    vul_bin = e[1] # vulnerable version
    patched_bin = e[2] # patched version
    func_name = e[3] # function name
    cveid = e[0]
    ida = "/home/angr/idapro-7.5/idat" # path to idal !!!
    # Patch Positioning start
    try:
        check_addr, patch_addr = diff_main(vul_bin, patched_bin, func_name, True, ida = ida)
        if check_addr == 0:
            raise Exception("patch addr is 0")
    except Exception as e:
        l.error("[-] Diff Error: {} {} {} {}".format(cveid, patched_bin, vul_bin, func_name))
        l.error(traceback.format_exc())
        return False

    l.info("[+] check addr {}; ".format(hex(check_addr), ))
    if patch_addr is not None:
        l.info("[+] guard addr {} ".format(hex(patch_addr)))
    # Patch Positioning end

    # PoC Input Generation start
    input_gen(cveid, patched_bin, func_name, check_addr=check_addr, patch_addr=patch_addr, force_generation=True)

    # CVE Signature Generation
    generate_cve_sig(*e, force_generation=True)



# patch test
def patch_test():
    set_logger_level(logging.INFO)
    entry = "CVE-2015-0288,binaries/openssl/O0/openssl-1.0.1k,X509_to_X509_REQ"
    splited = entry.strip().split(',')
    target_bin = os.path.join(rootdir, splited[1]) # target version
    func_name = splited[2]
    CVEID = splited[0] # important!
    func_to_detect = splited[-1]
    v = PatchDetection(CVE=CVEID, target_bin=target_bin, vul_func_name=func_name,
                       force_new=True, to_detect_func_name=func_to_detect)
    print(v)

if __name__ == '__main__':
    PoC_Sig_Gen()
    # patch_test()
