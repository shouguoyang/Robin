# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     taint_bv
   Description :
   Author :       None
   date：          2021/4/13
-------------------------------------------------
   Change Activity:
                   2021/4/13:
-------------------------------------------------
"""
from claripy import ClaripyValueError, FPS
from claripy.ast.bv import BV
from claripy.ast.fp import FP, _fp_length_calc
from claripy import simplifications, operations
from claripy.fp import FSort, FPV
import logging
import time


l = logging.getLogger('taint_bv')
l.setLevel(logging.DEBUG)


class NotConcreteError(TypeError):
    pass


class TaintFPV(FPV):
    # def __new__(cls, bv, sort, taint_tags, **kwargs):
    #     taint_tags = set()
    #     if 'taint_tags' in kwargs:
    #         taint_tags = ['taint_tags']
    #         kwargs.__delitem__('taint_tags')
    #
    #     if 'length' not in kwargs:
    #         kwargs['length'] = sort.length
    #
    #     if not isinstance(bv, claripy.ast.bv.BV):
    #         raise AttributeError("You need pass a BV to init TaintFPV")
    #
    #     return super().__new__(cls, 'fpToFP', (bv, sort), **kwargs)
    def __new__(cls, *args, **kwargs):
        return kwargs['bv']

    def __init__(self, value, sort, *args, **kwargs):
        super().__init__(value, sort)
        self._taint_tags = args[0]

    @property
    def tags(self):
        return self._taint_tags

    @tags.setter
    def tags(self, tags: set):
        self._taint_tags = tags

    def is_taint(self):
        if len(self._taint_tags) > 0:
            return True

    def untaint(self):
        self._taint_tags = set()

    @property
    def symbolic(self):
        return False

    def add_taint_source(self, source_name):
        '''
        :param source_name: set or string
        '''
        if type(source_name) is str:
            self._taint_tags.add(source_name)
        elif type(source_name) is set:
            self._taint_tags |= source_name
        else:
            raise TypeError("{} is not string or set".format(source_name))

    def _from_BV(self, bv: FP):
        '''convert bv to taintBV. If bv is symboic, return bv itself.'''
        value, size = bv.args
        return BVV(value, size, set())

    def raw_to_bv(self):
        '''Important!!! This function is used in memory/register store.'''
        return self

    def __float__(self):
        return self.value


# TaintFPV.__name__ = 'float'  # to call FP_from_FPV method



class TaintBV(BV):
    '''It can Not be SYMBOLIC!!!'''

    def __new__(cls, op, *args, **kwargs):
        if 'taint_tags' in kwargs:
            kwargs.__delitem__('taint_tags')
        return super().__new__(cls, op, *args, **kwargs)

    def __init__(self, op, *args, **kwargs):
        '''
        :param value:   The value. Either an integer or a bytestring. If it's the latter, it will be interpreted as the
                    bytes of a big-endian constant.
        :param size:    The size (in bits) of the bit-vector. Optional if you provide a string, required for an integer.
        :param taint_tags: set: the tags of taint variables which influence this BV
        '''
        super().__init__(op, *args, **kwargs)
        self._value, self._size = args[0]
        self._taint_tags = kwargs['taint_tags']

    @property
    def tags(self):
        return self._taint_tags

    @tags.setter
    def tags(self, tags: set):
        self._taint_tags = tags

    def is_taint(self):
        if len(self._taint_tags) > 0:
            return True

    def untaint(self):
        self._taint_tags = set()

    def add_taint_source(self, source_name):
        '''
        :param source_name: set or string
        '''
        if type(source_name) is str:
            self._taint_tags.add(source_name)
        elif type(source_name) is set:
            self._taint_tags |= source_name
        else:
            raise TypeError("{} is not string or set".format(source_name))

    def _from_BV(self, bv: BV):
        '''convert bv to taintBV. If bv is symboic, return bv itself.'''
        if bv.symbolic:
            return bv
        value, size = bv.args
        return BVV(value, size, set())

    def raw_to_bv(self):
        '''Important!!! This function is used in memory/register store.'''
        return self

    '''It is called when arithmetic operations. It return a new object with given op and args'''

    def make_like(self, op, args, **kwargs):

        if kwargs.pop("simplify", False) is True:
            # Try to simplify the expression again
            simplified = simplifications.simpleton.simplify(op, args)
        else:
            simplified = None
        if simplified is not None:
            op = simplified.op

        all_operations = operations.leaf_operations_symbolic | {'union'}
        if 'annotations' not in kwargs: kwargs['annotations'] = self.annotations
        if 'variables' not in kwargs and op in all_operations: kwargs['variables'] = self.variables
        if 'uninitialized' not in kwargs: kwargs['uninitialized'] = self._uninitialized
        if 'symbolic' not in kwargs and op in all_operations: kwargs['symbolic'] = self.symbolic
        # None
        if 'taint_tags' not in kwargs: kwargs['taint_tags'] = set()

        if simplified is None:
            # Cannot simplify the expression anymore
            if len(args) > 1:
                length = args[1]
            else:
                length = 32
            return type(self)(op, args, length=length, **kwargs)
        else:
            # The expression is simplified
            r = type(self)(op, simplified.args, length=simplified.args[1], **kwargs)
            return r


def TBV_from_BV(bv: BV, tag: set):
    if bv.symbolic:
        raise NotConcreteError("TaintBV can not be symbolic")
    value, size = bv.args
    return BVV(value, size, tag, bv = bv)


def BVV(value, size, taint_tag, **kwargs):
    """
    Creates a bit-vector value (i.e., a concrete value).

    :param value:   The value. Either an integer or a bytestring. If it's the latter, it will be interpreted as the
                    bytes of a big-endian constant.
    :param size:    The size (in bits) of the bit-vector. Optional if you provide a string, required for an integer.
    :param taint_tag: set or string: a tag to a tainted variable
    :returns:       A BV object representing this value.
    """
    if isinstance(size, FSort):
        return TaintFPV(value, size, taint_tag, **kwargs)
    if 'bv' in kwargs:
        kwargs.__delitem__('bv')
    if type(value) in (bytes, bytearray, memoryview, str, float):
        if type(value) is str:
            l.warning("BVV value is a unicode string, encoding as utf-8")
            value = value.encode('utf-8')

        if size is None:
            size = len(value) * 8
        elif type(size) is not int:
            raise TypeError("Bitvector size  must be either absent (implicit) or an integer")
        elif size != len(value) * 8:
            raise ClaripyValueError('string/size mismatch for BVV creation')

        value = int.from_bytes(value, 'big')

    elif size is None or (type(value) is not int and value is not None):
        raise TypeError('BVV() takes either an integer value and a size or a string of bytes')

    # ensure the 0 <= value < (1 << size)
    # FIXME hack to handle None which is used for an Empty Strided Interval (ESI)
    if value is not None:
        value &= (1 << size) - 1

    # hash = int : To avoid triggering the cache mechanism from father class Base of BV and returning same object.
    result = TaintBV('BVV', (value, size), length=size, taint_tags=taint_tag, hash=int(time.time() * 1000000), **kwargs)
    return result



if __name__ == '__main__':
    #test TFP
    import claripy
    bv = claripy.BVV(0x10, 32)
    fp = bv.raw_to_fp()
    x = TBV_from_BV(bv, set('test',))
    print(type(x))
    assert isinstance(x, claripy.ast.Base)