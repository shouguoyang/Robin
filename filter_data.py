# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     filter_data
   Description :
   Author :       None
   date：          2020/12/16
-------------------------------------------------
   Change Activity:
                   2020/12/16:
-------------------------------------------------
"""
__author__ = 'None'
import csv
import os
import json

black_list_all_simple_path = {
    "CVE-2017-13055",
    'CVE-2017-13046',  # all_simple_path 时间太长
    'CVE-2017-12994',  # all_simple_path 时间太长
    "CVE-2017-12991",  # all_simple_path 时间太长
    "CVE-2017-9042",  # all_simple_path 时间太长
    "CVE-2017-9040",  # all_simple_path 时间太长
    "CVE-2012-1132",  # all_simple_path 时间太长
    "CVE-2017-9995",  # all_simple_path
}
# 找不到路径生成state名单

no_path_for_state = {"CVE-2016-6671", "CVE-2016-6920", "CVE-2016-7562", "CVE-2016-7905", "CVE-2017-13688",
                     "CVE-2017-14767", "CVE-2017-7862", "CVE-2017-9991", "CVE-2018-10001", "CVE-2018-6392",
                     "CVE-2018-6621", "CVE-2018-7557"}
no_path_founded = {'CVE-2010-5298', 'CVE-2014-3505', 'CVE-2014-3507', 'CVE-2014-3569', 'CVE-2015-0287', 'CVE-2016-2180',
                   'CVE-2016-6671', 'CVE-2016-6920', 'CVE-2016-7562', 'CVE-2016-7905', 'CVE-2017-13055',
                   'CVE-2017-13688', 'CVE-2017-14767', 'CVE-2017-7862', 'CVE-2017-9991', 'CVE-2018-10001',
                   'CVE-2018-12700', 'CVE-2018-6392', 'CVE-2018-6621', 'CVE-2018-7557'}

# diff error， 找不到函数名
diff_error = {'CVE-2017-14745', 'CVE-2018-7642', 'CVE-2017-7302', 'CVE-2017-9040', 'CVE-2017-7300', 'CVE-2016-7450',
              'CVE-2017-14129', 'CVE-2017-9992', 'CVE-2017-15025', 'CVE-2015-3194', 'CVE-2017-9955', 'CVE-2018-7568',
              'CVE-2017-7223', 'CVE-2018-20673', 'CVE-2012-2686', 'CVE-2017-14934', 'CVE-2018-18701', 'CVE-2017-9039',
              'CVE-2017-15023', 'CVE-2018-12698', 'CVE-2017-16828', 'CVE-2017-9042', 'CVE-2016-2107', 'CVE-2017-15024',
              'CVE-2018-6872', 'CVE-2017-12967', 'CVE-2017-17126', 'CVE-2018-10535', 'CVE-2017-14939', 'CVE-2017-15022',
              'CVE-2018-17985', 'CVE-2018-17359', 'CVE-2017-17122', 'CVE-2017-17124', 'CVE-2017-16831',
              'CVE-2018-20657', 'CVE-2014-3509', 'CVE-2017-14974', 'CVE-2017-9954', 'CVE-2017-15020', 'CVE-2018-20002',
              'CVE-2017-14128', 'CVE-2017-15939', 'CVE-2017-9991', 'CVE-2017-9755', 'CVE-2018-10372', 'CVE-2017-15225',
              'CVE-2017-8392', 'CVE-2018-12934', 'CVE-2017-8421', 'CVE-2014-5139', 'CVE-2015-1792', 'CVE-2017-7301',
              'CVE-2017-14130', 'CVE-2018-6323', 'CVE-2017-7303', 'CVE-2014-3506', 'CVE-2018-19931', 'CVE-2017-14940',
              'CVE-2018-20623', 'CVE-2017-14933', 'CVE-2017-16829', 'CVE-2017-14930', 'CVE-2018-18607',
              'CVE-2018-12697', 'CVE-2018-17360', 'CVE-2017-15938', 'CVE-2018-7643', 'CVE-2017-15996', 'CVE-2017-13757',
              'CVE-2017-14938', 'CVE-2017-7304', 'CVE-2017-14729', 'CVE-2017-9995', 'CVE-2017-7225', 'CVE-2017-9038',
              'CVE-2017-15021', 'CVE-2017-16827', 'CVE-2014-8504', 'CVE-2018-18483', 'CVE-2017-12448', 'CVE-2017-6969',
              'CVE-2017-14932', 'CVE-2017-7224'}

#
black_list = black_list_all_simple_path | no_path_for_state | no_path_founded

def find_avaliable_cve_func():
    cve_file_path = './data/cve_openssh_libpng_expat_xml2_exif'
    with open(cve_file_path + ".res", 'r') as cvefile:
        cvereader = csv.reader(cvefile)
        for cve_entry in list(cvereader):
            cveid, vul_bin, patched_bin, func_name, check_addr, patch_addr = cve_entry
            state_file = "./data/cve_inputs/{}+{}.state".format(cveid, func_name)
            if os.path.exists(state_file):
                print(",".join(cve_entry))


if __name__ == '__main__':
    find_avaliable_cve_func()
