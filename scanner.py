import sys

sys.dont_write_bytecode = True

if __name__ == "__main__":
    from dvscan.cli import main

    sys.exit(main())
