from sys import exit, argv
from subprocess import run
from os import scandir, chdir, getcwd

assert len(argv) > 1

script_file_name_path = getcwd() + "\\ntpowerinfo.py"
with scandir(argv[1]) as fd:
    chdir(argv[1])
    for e in fd:
        if any(e.name.endswith(ex) for ex in (".exe", ".dll", ".sys")):
            print("Process {}".format(e.name))
            p = run(["ida64.exe", "-c", "-A", "-S" + script_file_name_path, e.name])
