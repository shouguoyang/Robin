# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     Exceptions
   Description :
   date：          2021/1/5
-------------------------------------------------
   Change Activity:
                   2021/1/5:
-------------------------------------------------
"""


class StateFileNotExitsException(Exception):
    def __init__(self, statefile):
        self.statefile = statefile

    def __str__(self):
        return "the state file {} not found, please run generate_vulfunc_input first"\
            .format(self.statefile)