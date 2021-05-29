import unittest

def as_hex_str(b):
    return " ".join("{:02x}".format(x) for x in b)

if True:
    test_case = unittest.TestCase()
    assertEqual = test_case.assertEqual
    assertLessEqual = test_case.assertLessEqual
else:
    def noop(*argv, **argkw):
        pass
    assertEqual = noop
    assertLessEqual = noop