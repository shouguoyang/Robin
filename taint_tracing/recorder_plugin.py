# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     recorder_plugin
   Description :
   Author :       None
   date：          2021/4/13
-------------------------------------------------
   Change Activity:
                   2021/4/13:
-------------------------------------------------
"""
__author__ = 'None'

import angr
from taint_tracing import TaintRecorder

class TaintRecorder_plugin(angr.SimStatePlugin):

    def __init__(self):
        super().__init__()
        self._taint_recorder = None

    def init_state(self):
        if self._taint_recorder is None:
            self._taint_recorder = TaintRecorder(self.state.arch)

    @property
    def taint_recorder(self):
        return self._taint_recorder

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new = TaintRecorder_plugin()
        new._taint_recorder = self._taint_recorder
        return new