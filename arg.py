import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--output", choices=["terminal", "logs", "both"], default="both")
args = parser.parse_args()

print(f"output: {args.output}")
