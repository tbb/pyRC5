# -*- coding: utf-8 -*-
import platform


class RC5:

    def __init__(self, W, R, key):
        self.W = W
        self.R = R
        self.b = len(key)
        self.key = key
        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __convert(self, val):
        return list(bin(abs(val))[2:].zfill(self.W))

    def __shift(self, val, n):
        val, n = self.__convert(val), n % self.W
        return int(''.join(val[n:] + val[:n]), 2)

    def __unshift(self, val, n):
        val, n = self.__convert(val), n % self.W
        return int(''.join(val[-n:] + val[:-n]), 2)

    def __const(self):
        if self.W == 16:
            return (0xB7E1, 0x9E37)
        elif self.W == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif self.W == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    def __keyAlign(self):
        while len(self.key) % (self.W // 8):
            self.key += b'\x00'
        self.c = len(self.key) // (self.W // 8)
        L, key = [], bin(int.from_bytes(self.key, byteorder='big'))[2:]
        for i in range(self.c):
            L.append(int(key[:self.W], 2))
            key = key[self.W:]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % 2 ** self.W for i in range(2 * self.R + 1)]

    def __shuffle(self):
        m = max(self.c, 2 * self.R + 1)
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * m):
            A = self.S[i] = self.__shift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__shift((self.L[j] + A + B), A + B)
            i = (i + 1) % (2 * self.R + 1)
            j = (j + 1) % self.c

    def encrypt(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            while True:
                text = inp.read(self.W // 4)
                if not text:
                    break
                text = text.ljust(self.W // 4, b'\x00')
                A = int.from_bytes(text[:self.W // 8], byteorder='big')
                B = int.from_bytes(text[self.W // 8:], byteorder='big')
                A = (A + self.S[0]) % 2 ** self.W
                B = (B + self.S[1]) % 2 ** self.W
                for i in range(1, self.R):
                    A = (self.__shift((A ^ B), B)
                         + self.S[2 * i]) % 2 ** self.W
                    B = (self.__shift((A ^ B), A)
                         + self.S[2 * i + 1]) % 2 ** self.W

                out.write(A.to_bytes(self.W // 8, byteorder='big') +
                          B.to_bytes(self.W // 8, byteorder='big'))

    def decrypt(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            while True:
                text = inp.read(self.W // 4)
                if not text:
                    break
                A = int.from_bytes(text[:self.W // 8], byteorder='big')
                B = int.from_bytes(text[self.W // 8:], byteorder='big')
                for i in range(self.R - 1, 0, -1):
                    B = self.__unshift(
                        ((B - self.S[2 * i + 1]) % 2 ** self.W), A) ^ A
                    A = self.__unshift(
                        ((A - self.S[2 * i]) % 2 ** self.W), B) ^ B
                B = (B - self.S[1]) % 2 ** self.W
                A = (A - self.S[0]) % 2 ** self.W
                res = (A.to_bytes(self.W // 8, byteorder='big')
                       + B.to_bytes(self.W // 8, byteorder='big'))
                out.write(res.rstrip(b'\x00'))


if __name__ == "__main__":
    if platform.architecture()[0].startswith('32'):
        W = 32
    elif platform.architecture()[0].startswith('64'):
        W = 64
    else:
        raise Exception("What's going on!?")
    R = 12
    key = b"testkeyforRCdef"

    R = RC5(W, R, key)
    R.encrypt("input2.txt", "encrypt.txt")
    R.decrypt("encrypt.txt", "decrypt.txt")
