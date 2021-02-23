from patch_detection import *


################ Tests ##################################
from patch_location.PatchLocation import diff_main


def cfg_gen():
    from tqdm import tqdm

    def gen_cfg(binPath):
        cfg_path = binPath + ".angr_cfg"
        if not os.path.exists(cfg_path):
            try:
                l.debug("{}".format(cfg_path))
                p = angr.Project(binPath, auto_load_libs="False")
                cfg = p.analyses.CFGFast()
                pickle.dump(cfg, open(cfg_path, 'wb'))
            except Exception as e:
                l.error(e.args)

    cve_file_path = './data/cve_openssh_libpng_expat_xml2_exif'
    with open(cve_file_path, 'r') as cvefile:
        cvereader = csv.reader(cvefile)
        next(cvereader)
        for cve_entry in tqdm(list(cvereader)):
            cveid, vul_bin, patched_bin, func_name = cve_entry
            if 'openssh' in vul_bin:
                vul_bin = os.path.join(rootdir, vul_bin)
                patched_bin = os.path.join(rootdir, patched_bin)
                # gen_cfg(vul_bin)
                print(patched_bin)
                gen_cfg(patched_bin)


# 签名生成测试
def test_sig():
    cvestr = \
"CVE-2016-1907,binaries/openssh/O0/openssh-7.1p1/ssh-keysign,binaries/openssh/O0/openssh-7.1p2/ssh-keysign,ssh_packet_read_poll2"
    set_logger_level(logging.DEBUG)
    e = cvestr.split(",")
    vul_bin = e[1]
    patched_bin = e[2]
    func_name = e[3]
    cveid = e[0]
    try:
        check_addr, patch_addr = diff_main(vul_bin, patched_bin, func_name, True)
        if check_addr == 0:
            raise Exception("patch addr is 0")
    except Exception as e:
        l.error("[-] Diff Error: {} {} {} {}".format(cveid, patched_bin, vul_bin, func_name))
        l.error(traceback.format_exc())
        return False

    l.info("[+] check addr {}; ".format(hex(check_addr), ))
    if patch_addr is not None:
        l.info("[+] patch addr {} ".format(hex(patch_addr)))
    input_gen(cveid, patched_bin, func_name, check_addr=check_addr, patch_addr=patch_addr, force_generation=True)
    generate_cve_sig(*e, force_generation=True)



# 补丁检测测试
def patch_test():
    set_logger_level(logging.DEBUG)
    entry = "CVE-2015-1791,binaries/openssl/O0/openssl-1.0.1o,ssl3_get_new_session_ticket"
    splited = entry.strip().split(',')
    target_bin = os.path.join(rootdir, splited[1])
    func_name = splited[2]
    CVEID = splited[0]
    func_to_detect = splited[-1]
    v = PatchDetection(CVE=CVEID, target_bin=target_bin, vul_func_name=func_name,
                       force_new=True, to_detect_func_name=func_to_detect)
    print(v)

if __name__ == '__main__':
    # cfg_gen()
    test_sig()
    # patch_test()
