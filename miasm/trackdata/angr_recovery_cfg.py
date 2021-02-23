import angr
import time
import networkx as nx
#from angrutils import *

def get_func_blcoks_addr(cfg,func_addr):
    nodes=list(cfg.model.nodes())
    func_nodes=set([])
    for node in nodes:
        if(node.function_address==func_addr):
            func_nodes.add(node.addr)
    return func_nodes

def cfg_recovery(file_absolute_path,funcAddr ):
    analyses_file=file_absolute_path
    #initialization
    proj=angr.Project(analyses_file,auto_load_libs=False)
    main_addr=proj.loader.main_object.mapped_base
    rebased_addr=main_addr+funcAddr
    #print(str(hex(rebased_addr)))
    # cfg=proj.analyses.CFGEmulated(start=rebased_addr,context_sensitivity_level=2,keep_state=True,
    # state_add_options=angr.sim_options.refs)

    #use angr output cfg
    #cfg=proj.analyses.CFGFast(start=funcAddr)
    #state=proj.factory.blank_state(addr=rebased_addr)
    cfg=proj.analyses.CFGFast(function_starts=[funcAddr])
    # plot_cfg(cfg, "%s_cfg" % ('test'), format='svg',asminst=True, vexinst=False,
    #          func_addr={rebased_addr:True}, debug_info=True, remove_imports=False, remove_path_terminator=False)
    recov_cfg={}
    temp=set([])
    loaded_addr=main_addr
    # for i in cfg.graph.nodes():
    #     temp.add(i.addr-loaded_addr)
    # print(len(temp))
    # from collections import Counter
    # temp=list(temp)
    # aa=Counter(temp)
    
    for src,dst in cfg.graph.edges():
        temp=recov_cfg.get(src.addr-loaded_addr,set([]))
        temp.add(dst.addr-loaded_addr)
        recov_cfg[src.addr-loaded_addr]=temp
        if((dst.addr-loaded_addr) not in recov_cfg):
            recov_cfg[dst.addr-loaded_addr]=set([])
    # b=[i for i in recov_cfg.keys()]
    # bb=Counter(b)
    # print(aa-bb)
    # print(len(recov_cfg))
    # print(len(cfg.graph.nodes()))
    # print(recov_cfg[0xabfd])
    #print(len(recov_cfg))
    #print(recov_cfg)
    return recov_cfg


if __name__=='__main__':
    time_start=time.time()
    cfg_recovery('/mnt/sharing/angrforward/curl_7.54.1.so',0x1310e)
    time_end=time.time()
    print('total cost:',time_end-time_start)
