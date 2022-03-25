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
# white_list = ['CVE-2010-2806', 'CVE-2010-3814', 'CVE-2010-3855', 'CVE-2011-0539', 'CVE-2012-1126', 'CVE-2012-1128', 'CVE-2012-1129', 'CVE-2012-1130', 'CVE-2012-1131', 'CVE-2012-1133', 'CVE-2012-1135', 'CVE-2012-1136', 'CVE-2012-1139', 'CVE-2012-1140', 'CVE-2012-1141', 'CVE-2012-1142', 'CVE-2012-1144', 'CVE-2012-2840', 'CVE-2013-0166', 'CVE-2013-2877', 'CVE-2013-4353', 'CVE-2013-4548', 'CVE-2013-6449', 'CVE-2013-6450', 'CVE-2014-0160', 'CVE-2014-0195', 'CVE-2014-0198', 'CVE-2014-0221', 'CVE-2014-0224', 'CVE-2014-3470', 'CVE-2014-3505', 'CVE-2014-3507', 'CVE-2014-3508', 'CVE-2014-3510', 'CVE-2014-3511', 'CVE-2014-3512', 'CVE-2014-3513', 'CVE-2014-3567', 'CVE-2014-3572', 'CVE-2014-8176', 'CVE-2014-8275', 'CVE-2014-8502', 'CVE-2014-8738', 'CVE-2014-9657', 'CVE-2014-9658', 'CVE-2014-9661', 'CVE-2014-9662', 'CVE-2014-9663', 'CVE-2014-9664', 'CVE-2014-9666', 'CVE-2014-9667', 'CVE-2014-9668', 'CVE-2014-9669', 'CVE-2014-9670', 'CVE-2014-9671', 'CVE-2014-9673', 'CVE-2014-9674', 'CVE-2015-0204', 'CVE-2015-0205', 'CVE-2015-0206', 'CVE-2015-0209', 'CVE-2015-0286', 'CVE-2015-0288', 'CVE-2015-0289', 'CVE-2015-0293', 'CVE-2015-1788', 'CVE-2015-1789', 'CVE-2015-1790', 'CVE-2015-1791', 'CVE-2015-3195', 'CVE-2015-3196', 'CVE-2015-3197', 'CVE-2015-5352', 'CVE-2015-8126', 'CVE-2015-8472', 'CVE-2015-8540', 'CVE-2016-0702', 'CVE-2016-0703', 'CVE-2016-0704', 'CVE-2016-0705', 'CVE-2016-0778', 'CVE-2016-0798', 'CVE-2016-10190', 'CVE-2016-1907', 'CVE-2016-2105', 'CVE-2016-2106', 'CVE-2016-2109', 'CVE-2016-2176', 'CVE-2016-2177', 'CVE-2016-2178', 'CVE-2016-2179', 'CVE-2016-2180', 'CVE-2016-2181', 'CVE-2016-2182', 'CVE-2016-3115', 'CVE-2016-5199', 'CVE-2016-6164', 'CVE-2016-6302', 'CVE-2016-6303', 'CVE-2016-6304', 'CVE-2016-6306', 'CVE-2016-6515', 'CVE-2016-7122', 'CVE-2016-7450', 'CVE-2016-7905', 'CVE-2017-1000460', 'CVE-2017-11108', 'CVE-2017-11399', 'CVE-2017-11665', 'CVE-2017-11719', 'CVE-2017-12448', 'CVE-2017-12893', 'CVE-2017-12894', 'CVE-2017-12896', 'CVE-2017-12897', 'CVE-2017-12899', 'CVE-2017-12901', 'CVE-2017-12902', 'CVE-2017-12989', 'CVE-2017-12990', 'CVE-2017-12992', 'CVE-2017-12993', 'CVE-2017-12995', 'CVE-2017-13000', 'CVE-2017-13002', 'CVE-2017-13004', 'CVE-2017-13006', 'CVE-2017-13010', 'CVE-2017-13011', 'CVE-2017-13014', 'CVE-2017-13015', 'CVE-2017-13016', 'CVE-2017-13020', 'CVE-2017-13022', 'CVE-2017-13023', 'CVE-2017-13024', 'CVE-2017-13025', 'CVE-2017-13026', 'CVE-2017-13027', 'CVE-2017-13028', 'CVE-2017-13030', 'CVE-2017-13031', 'CVE-2017-13033', 'CVE-2017-13035', 'CVE-2017-13037', 'CVE-2017-13038', 'CVE-2017-13039', 'CVE-2017-13042', 'CVE-2017-13044', 'CVE-2017-13045', 'CVE-2017-13047', 'CVE-2017-13049', 'CVE-2017-13052', 'CVE-2017-13053', 'CVE-2017-13054', 'CVE-2017-13688', 'CVE-2017-13689', 'CVE-2017-13725', 'CVE-2017-14054', 'CVE-2017-14055', 'CVE-2017-14056', 'CVE-2017-14058', 'CVE-2017-14059', 'CVE-2017-14128', 'CVE-2017-14129', 'CVE-2017-14169', 'CVE-2017-14170', 'CVE-2017-14171', 'CVE-2017-14222', 'CVE-2017-14223', 'CVE-2017-14767', 'CVE-2017-14930', 'CVE-2017-14932', 'CVE-2017-14933', 'CVE-2017-14934', 'CVE-2017-14938', 'CVE-2017-14939', 'CVE-2017-15020', 'CVE-2017-15023', 'CVE-2017-15024', 'CVE-2017-15025', 'CVE-2017-15225', 'CVE-2017-15938', 'CVE-2017-15939', 'CVE-2017-16827', 'CVE-2017-16829', 'CVE-2017-16831', 'CVE-2017-16840', 'CVE-2017-17122', 'CVE-2017-17124', 'CVE-2017-17126', 'CVE-2017-5024', 'CVE-2017-5025', 'CVE-2017-7302', 'CVE-2017-7303', 'CVE-2017-7304', 'CVE-2017-7857', 'CVE-2017-7858', 'CVE-2017-7864', 'CVE-2017-8287', 'CVE-2017-8392', 'CVE-2017-8395', 'CVE-2017-8397', 'CVE-2017-8421', 'CVE-2017-9038', 'CVE-2017-9233', 'CVE-2017-9608', 'CVE-2017-9955', 'CVE-2017-9990', 'CVE-2017-9991', 'CVE-2017-9993', 'CVE-2017-9994', 'CVE-2018-10373', 'CVE-2018-10535', 'CVE-2018-12458', 'CVE-2018-13033', 'CVE-2018-13300', 'CVE-2018-13302', 'CVE-2018-14395', 'CVE-2018-17358', 'CVE-2018-18309', 'CVE-2018-18605', 'CVE-2018-18606', 'CVE-2018-20002', 'CVE-2018-20671', 'CVE-2018-20712', 'CVE-2018-6543', 'CVE-2018-6759', 'CVE-2018-6872', 'CVE-2018-7751', 'CVE-2018-8945']
with open('/home/angr/PatchDiff/data/whitelist.json') as f:
    white_list = json.load(f)

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