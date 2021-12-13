import collections
import pprint

DEBUG = False

HuffmanTreeLeaf = collections.namedtuple('HuffmanTreeLeaf', ['isLeaf', 'node_value', 'in_path', 'path', 'has_child_0', 'has_child_1'])

class HuffmanTreeNode(object):
    def __init__(self, node_value = None, child_0=None, child_1=None, path=''):
        self._children = [child_0, child_1]
        self._node_value = node_value
        self._path = path
    
    def __str__(self):
        return "HuffmanTreeNode(has_child_0=%5s, has_child_1=%5s, in_path=%-10s, node_value=%s)" % (
            self._children[0] is not None, 
            self._children[1] is not None,
            self._path,
            self._node_value)
        
    def tree_to_str(self):
        # return pprint.pformat(self.as_dict())
        return pprint.pformat(["HuffmanTreeLeaf(isLeaf=%5s, in_path=%-10s, path=%-10s, node_value=%s)" % (n.isLeaf, n.in_path, n.path, n.node_value)
            for n in sorted(self.as_tuples(), key=lambda x: x.path)], width=100)
        
    def as_dict(self):
        return {
            'node_value': self._node_value,
            'child_0': None if self._children[0] is None else self._children[0].as_dict(),
            'child_1': None if self._children[1] is None else self._children[1].as_dict(),
        }
        
    def as_tuples(self, prefix=''):
        retval = []
        if self._node_value is not None:
            retval.append(HuffmanTreeLeaf(self.is_leaf(), self._node_value, self._path, prefix, self._children[0] is not None, self._children[1] is not None))
        
        if self._children[0]:
            retval.extend(self._children[0].as_tuples(prefix + '0'))
        if self._children[1]:
            retval.extend(self._children[1].as_tuples(prefix + '1'))
            
        return retval
    
    def get_node_value(self): # get_huffman_index()
        if not self.is_leaf():
            raise ValueError('Invalid node. A non-leaf node does not have a node_value. %s' % self)
        if self._node_value is None:
            raise ValueError('Invalid node. This leaf node does not have a node_value. %s' % self)
        return self._node_value

    def next_value_from(self, bits_iter): # next_huffman_index_from()
        tree_node = self
        while not tree_node.is_leaf():
            tree_node = tree_node.get_child(bits_iter.next())
        return tree_node.get_node_value()

    def has_children(self):
        return (self._children[0] is not None) or (self._children[1] is not None)
    
    def is_leaf(self):
        return (self._node_value is not None) and not self.has_children()
        
    def get_child(self, digit):
        if digit != 0 and digit != 1:
            raise ValueError('Invalid binary digit "%s"' % digit)
        return self._children[digit]
            
    def add_child(self, node_value, prefix, prefix_length, digits_low_to_high = False):
        try:
            digits = []
            for i in range(prefix_length):
                digits.append(prefix & 0x01)
                prefix >>= 1
            if not digits_low_to_high:
                digits = digits[::-1]
            if DEBUG: print('Adding to Tree: digits=%s, node_value=%s' % (digits, node_value))
            self._add_child(node_value, digits)
        except Exception as e:
            raise ValueError('Error building Huffman tree. Partial tree: %s' % (self.tree_to_str(),)) from e
        
    def _add_child(self, node_value, digits, index = 0):
        if len(digits) <= index:
            if self.has_children():
                raise ValueError('Invalid node. A Node must have children or have a value but not both. %s' % self)
            self._node_value = node_value
            if DEBUG: print('Adding child: node_value=%s, digit=N/A to %s' % (node_value, self))
            return
        digit = digits[index]
        if digit != 0 and digit != 1:
            raise ValueError('Invalid binary digit "%s"' % digit)
        if self._children[digit] is None:
            self._children[digit] = HuffmanTreeNode(path=''.join(('%s' % d for d in digits[:index+1])))
        if self._children[digit].is_leaf():
            raise ValueError('Invalid operation: _add_child. A Node must have children or have a value but not both. %s, huff_index=%s, digit_index=%s, digits=%s' % (self._children[digit], node_value, index + 1, digits))
        
        if DEBUG: print('Adding child: node_value=%s, digit=%-3s to %s' % (node_value, digits[index], self))
        self._children[digit]._add_child(node_value, digits, index + 1)
