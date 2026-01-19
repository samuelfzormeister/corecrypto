import tokenize
import argparse

parser = argparse.ArgumentParser(
    prog="rsp_parser", description="A basic parser for the NIST's RSP files."
)

parser.add_argument("-f", "--file")


def parse_rsp(rsp):
    print("parsing...")


def main():
    args = parser.parse_args()
    path = args.file

    # ugh, it spits and error at me :(
    with open(path, "rb") as f:
        tokens = tokenize.tokenize(f.readline)
        for token in tokens:
            print(token)


if __name__ == "__main__":
    main()
