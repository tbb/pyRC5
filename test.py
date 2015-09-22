import RC5
import unittest
import os
import tempfile

INIT_DATA = """
        The Zen of Python, by Tim Peters

        Beautiful is better than ugly.
        Explicit is better than implicit.
        Simple is better than complex.
        Complex is better than complicated.
        Flat is better than nested.
        Sparse is better than dense.
        Readability counts.
        Special cases aren't special enough to break the rules.
        Although practicality beats purity.
        Errors should never pass silently.
        Unless explicitly silenced.
        In the face of ambiguity, refuse the temptation to guess.
        There should be one-- and preferably only one --obvious way to do it.
        Although that way may not be obvious at first unless you're Dutch.
        Now is better than never.
        Although never is often better than *right* now.
        If the implementation is hard to explain, it's a bad idea.
        If the implementation is easy to explain, it may be a good idea.
        Namespaces are one honking great idea -- let's do more of those!
        """
TEST_KEY = b"MontyPython"


class RC5TestCase(unittest.TestCase):

    def setUp(self):
        self.input_fd, self.input_filename = tempfile.mkstemp(dir=os.curdir)
        self.out_fd, self.out_filename = tempfile.mkstemp(dir=os.curdir)
        with open(self.input_filename, 'w') as data_file:
            data_file.write(INIT_DATA)

    def tearDown(self):
        os.close(self.input_fd)
        os.unlink(self.input_filename)
        os.close(self.out_fd)
        os.unlink(self.out_filename)

    def test_RC5_six_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 6, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()

    def test_RC5_twelve_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 12, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()

    def test_RC5_eighteen_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 18, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()

    def test_RC5_twentyfour_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 24, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()

    def test_RC5_thirty_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 30, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()

    def test_RC5_thirtysix_rounds_crypt(self):
        testRC5 = RC5.RC5(64, 6, TEST_KEY)
        testRC5.encrypt(self.input_filename, self.out_filename)
        testRC5.decrypt(self.out_filename, self.input_filename)
        with open(self.input_filename, 'r') as f:
            assert INIT_DATA == f.read()


if __name__ == "__main__":
    unittest.main()
