
from argparse import ArgumentParser

# from .io import readBinaryFileAtPath
# from .macho import MachO


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)

    args = parser.parse_args()

    if args.i:
        # input_data = readBinaryFileAtPath(args.i[0])
        # macho = MachO(input_data)

        pass


if __name__ == '__main__':
    main()
