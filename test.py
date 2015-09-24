import RC5
import unittest
import os
import tempfile


class RC5FileTests(unittest.TestCase):

    def setUp(self):
        self.input_fd, self.input_filename = tempfile.mkstemp(dir=os.curdir)
        self.out_fd, self.out_filename = tempfile.mkstemp(dir=os.curdir)

    def tearDown(self):
        os.close(self.input_fd)
        os.unlink(self.input_filename)
        os.close(self.out_fd)
        os.unlink(self.out_filename)

    def test1(self):
        testRC5 = RC5.RC5(32, 12, b'\0' * 16)
        plainText = b'\0' * 8
        with open(self.input_filename, 'wb') as data_file:
            data_file.write(plainText)
        testRC5.encryptFile(self.input_filename, self.out_filename)
        cipherText = b'\x21\xA5\xDB\xEE\x15\x4B\x8F\x6D'
        with open(self.out_filename, 'rb') as data_file:
            assert cipherText == data_file.read()
        testRC5.decryptFile(self.out_filename, self.input_filename)
        with open(self.input_filename, 'rb') as data_file:
            assert plainText == data_file.read()

    def test2(self):
        key = b'\x91\x5F\x46\x19\xBE\x41\xB2\x51\x63\x55\xA5\x01\x10\xA9\xCE\x91'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x21\xA5\xDB\xEE\x15\x4B\x8F\x6D'
        with open(self.input_filename, 'wb') as data_file:
            data_file.write(plainText)
        testRC5.encryptFile(self.input_filename, self.out_filename)
        cipherText = b'\xF7\xC0\x13\xAC\x5B\x2B\x89\x52'
        with open(self.out_filename, 'rb') as data_file:
            assert cipherText == data_file.read()
        testRC5.decryptFile(self.out_filename, self.input_filename)
        with open(self.input_filename, 'rb') as data_file:
            assert plainText == data_file.read()

    def test3(self):
        key = b'\x78\x33\x48\xE7\x5A\xEB\x0F\x2F\xD7\xB1\x69\xBB\x8D\xC1\x67\x87'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\xF7\xC0\x13\xAC\x5B\x2B\x89\x52'
        with open(self.input_filename, 'wb') as data_file:
            data_file.write(plainText)
        testRC5.encryptFile(self.input_filename, self.out_filename)
        cipherText = b'\x2F\x42\xB3\xB7\x03\x69\xFC\x92'
        with open(self.out_filename, 'rb') as data_file:
            assert cipherText == data_file.read()
        testRC5.decryptFile(self.out_filename, self.input_filename)
        with open(self.input_filename, 'rb') as data_file:
            assert plainText == data_file.read()

    def test4(self):
        key = b'\xDC\x49\xDB\x13\x75\xA5\x58\x4F\x64\x85\xB4\x13\xB5\xF1\x2B\xAF'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x2F\x42\xB3\xB7\x03\x69\xFC\x92'
        with open(self.input_filename, 'wb') as data_file:
            data_file.write(plainText)
        testRC5.encryptFile(self.input_filename, self.out_filename)
        cipherText = b'\x65\xC1\x78\xB2\x84\xD1\x97\xCC'
        with open(self.out_filename, 'rb') as data_file:
            assert cipherText == data_file.read()
        testRC5.decryptFile(self.out_filename, self.input_filename)
        with open(self.input_filename, 'rb') as data_file:
            assert plainText == data_file.read()

    def test5(self):
        key = b'\x52\x69\xF1\x49\xD4\x1B\xA0\x15\x24\x97\x57\x4D\x7F\x15\x31\x25'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x65\xC1\x78\xB2\x84\xD1\x97\xCC'
        with open(self.input_filename, 'wb') as data_file:
            data_file.write(plainText)
        testRC5.encryptFile(self.input_filename, self.out_filename)
        cipherText = b'\xEB\x44\xE4\x15\xDA\x31\x98\x24'
        with open(self.out_filename, 'rb') as data_file:
            assert cipherText == data_file.read()
        testRC5.decryptFile(self.out_filename, self.input_filename)
        with open(self.input_filename, 'rb') as data_file:
            assert plainText == data_file.read()


class RC5BytesTests(unittest.TestCase):

    def test1(self):
        testRC5 = RC5.RC5(32, 12, b'\0' * 16)
        plainText = b'\0' * 8
        cipherText = b'\x21\xA5\xDB\xEE\x15\x4B\x8F\x6D'
        assert testRC5.encryptBytes(plainText) == cipherText

    def test2(self):
        key = b'\x91\x5F\x46\x19\xBE\x41\xB2\x51\x63\x55\xA5\x01\x10\xA9\xCE\x91'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x21\xA5\xDB\xEE\x15\x4B\x8F\x6D'
        cipherText = b'\xF7\xC0\x13\xAC\x5B\x2B\x89\x52'
        assert testRC5.encryptBytes(plainText) == cipherText

    def test3(self):
        key = b'\x78\x33\x48\xE7\x5A\xEB\x0F\x2F\xD7\xB1\x69\xBB\x8D\xC1\x67\x87'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\xF7\xC0\x13\xAC\x5B\x2B\x89\x52'
        cipherText = b'\x2F\x42\xB3\xB7\x03\x69\xFC\x92'
        assert testRC5.encryptBytes(plainText) == cipherText

    def test4(self):
        key = b'\xDC\x49\xDB\x13\x75\xA5\x58\x4F\x64\x85\xB4\x13\xB5\xF1\x2B\xAF'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x2F\x42\xB3\xB7\x03\x69\xFC\x92'
        cipherText = b'\x65\xC1\x78\xB2\x84\xD1\x97\xCC'
        assert testRC5.encryptBytes(plainText) == cipherText

    def test5(self):
        key = b'\x52\x69\xF1\x49\xD4\x1B\xA0\x15\x24\x97\x57\x4D\x7F\x15\x31\x25'
        testRC5 = RC5.RC5(32, 12, key)
        plainText = b'\x65\xC1\x78\xB2\x84\xD1\x97\xCC'
        cipherText = b'\xEB\x44\xE4\x15\xDA\x31\x98\x24'
        assert testRC5.encryptBytes(plainText) == cipherText

if __name__ == "__main__":
    unittest.main()
