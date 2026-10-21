"""Second intentionally unsafe training example; analysis does not execute it."""


def dangerous_eval(user_input):
    return eval(user_input)


def dynamic_execution(source):
    exec(source)


def shell_command(user_input):
    import subprocess
    return subprocess.run(user_input, shell=True, capture_output=True, text=True)
