# pyRC5
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[![Build Status](https://travis-ci.org/tbb/pyRC5.svg?branch=master)](https://travis-ci.org/tbb/pyRC5)
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Unlike many schemes, RC5 has a variable block size (32, 64 or 128 bits), key size (0 to 2040 bits) and number of rounds (0 to 255). The original suggested choice of parameters were a block size of 64 bits, a 128-bit key and 12 rounds.

### Usage

There are two entrypoint script: encrypt and decrypt with the same interface.

```console
usage: encrypt.py [-h] -i INPUT_FILE -k KEY_FILE -o OUTPUT_FILE
                  [-w BLOCK_SIZE] [-r ROUND_SIZE]

Required arguments:
  -i INPUT_FILE, --input-file INPUT_FILE
                        Path to data file
  -k KEY_FILE, --key-file KEY_FILE
                        Path to key file
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Path to result file.

Optional arguments:
  -w BLOCK_SIZE, --block-size BLOCK_SIZE
                        RC5 block size. (32, 64 or 128 bits)
  -r ROUND_SIZE, --round-size ROUND_SIZE
                        RC5 round count. (0 to 255)
```

For example, assume that we have source.txt and key.rc5 files, then:
```console
python encrypt.py -i source.txt -o encrypted.txt -k key
python decrypt.py -i encrypted.txt -o decrypted.txt -k key 
```
