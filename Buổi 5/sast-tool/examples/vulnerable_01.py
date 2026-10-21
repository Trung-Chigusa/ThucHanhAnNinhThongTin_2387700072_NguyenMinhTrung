"""Intentionally unsafe training example. Do not use with untrusted input."""

import pickle

demo_credential = "DEMO_ONLY_NOT_A_SECRET"


def calculate(user_expression):
    return eval(user_expression)


def load_object(blob):
    return pickle.loads(blob)


if __name__ == "__main__":
    # Only a harmless arithmetic expression is evaluated in this demonstration.
    print(calculate("2 + 2"))
