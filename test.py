import unittest
import os
import re
import importlib

def load_tests(loader, standard_tests, pattern):
    # top level directory cached on loader instance
    this_dir = os.path.dirname(__file__)
    package_tests = loader.discover(start_dir=this_dir, pattern='test_*.py')
    standard_tests.addTests(package_tests)
    return standard_tests

# useful for running a single test by:
#
# ```
# test.py test_module.TestClass.test_method
# ```
def load_test_modules():
    this_dir = os.path.dirname(__file__)
    files = os.listdir(this_dir)
    # load the modules
    for f in files:
        if re.match('^test_.*\.py$', f):
            mod_name = f[:-3]
            mod = importlib.import_module(mod_name)
            globals()[mod_name] = mod
            
    
if __name__ == '__main__':
    load_test_modules()
    unittest.main()