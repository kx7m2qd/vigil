import os
import shlex
import subprocess
from pathlib import Path
from subprocess import Popen


def capture_dependencies(requirements_path):
    command = f"pigar gen -f {Path(requirements_path)} {os.getcwd()}"
    # ruleid: py-shell-formatted-command
    os.system(command)


def start_training(args, env):
    # ruleid: py-shell-formatted-command
    return Popen(f"llamafactory-cli train {args['config']}", env=env, shell=True)


def archive(name):
    # ruleid: py-shell-formatted-command
    subprocess.run("tar czf %s.tgz %s" % (name, name), shell=True, check=True)


def ping(host):
    # ruleid: py-shell-formatted-command
    return os.popen("ping -c 1 " + host).read()


def capture_dependencies_safe(requirements_path):
    # ok: py-shell-formatted-command
    subprocess.run(["pigar", "gen", "-f", str(Path(requirements_path)), os.getcwd()], check=True)


def start_training_safe(config, env):
    # ok: py-shell-formatted-command
    return Popen(["llamafactory-cli", "train", config], env=env)


def ping_safe(host):
    # ok: py-shell-formatted-command
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)


def list_tmp():
    # ok: py-shell-formatted-command
    os.system("ls -la /tmp")


def show(path):
    # ok: py-shell-formatted-command
    os.system(f"ls -la {shlex.quote(path)}")


def show_concat(path):
    # ok: py-shell-formatted-command
    os.system("ls -la " + shlex.quote(path))


PIGAR_VERSION = "2.1.4"


def install_pigar():
    # ok: py-shell-formatted-command
    os.system(f"pip install pigar=={PIGAR_VERSION}")


def run_shell(cmd):
    # A plain wrapper: the risk is at its call sites, not here.
    # ok: py-shell-formatted-command
    return subprocess.run(cmd, shell=True, check=True)


def echo_constant(param):
    bar = {"a": "a-Value", "b": param}["a"]
    # ok: py-shell-formatted-command
    os.system("echo " + shlex.quote(bar))
