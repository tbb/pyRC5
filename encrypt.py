import argparse

from RC5 import RC5

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser._action_groups.pop()
    required = parser.add_argument_group('Required arguments')
    optional = parser.add_argument_group('Optional arguments')
    required.add_argument('-i', '--input-file', help='Path to data file', required=True)
    required.add_argument('-k', '--key-file', help='Path to key file', required=True)
    required.add_argument('-o', '--output-file', help='Path to result file.', required=True)
    optional.add_argument('-w', '--block-size', help='RC5 block size. (32, 64 or 128 bits)', default=32)
    optional.add_argument('-r', '--round-size', help='RC5 round count. (0 to 255)', default=12)
    args = parser.parse_args()

    with open(args.key_file, 'rb') as key_file:
        key = key_file.read()

    rc5 = RC5(args.block_size, args.round_size, key)
    rc5.encryptFile(args.input_file, args.output_file)
