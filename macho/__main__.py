
from argparse import ArgumentParser

from .io import readBinaryFileAtPath
from .macho import MachO


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-kextNames', action='store_true')

    args = parser.parse_args()

    if not args.i or not args.kextNames:
        return parser.print_help()

    if args.i:
        input_data = readBinaryFileAtPath(args.i[0])
        macho = MachO(input_data)

        if args.kextNames:
            return macho.printKextNames()


if __name__ == '__main__':
    main()
