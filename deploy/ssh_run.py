"""远程执行命令：python ssh_run.py "command"  或  echo cmd | python ssh_run.py -"""
import os
import sys

import paramiko

from ssh_config import HOST, KEY, PWD, USER


def connect():
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=HOST,
        port=int(os.environ.get('KP_SSH_PORT', '22')),
        username=USER,
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        allow_agent=False,
    )
    if KEY:
        cli.connect(key_filename=KEY, look_for_keys=False, **kwargs)
    else:
        cli.connect(password=PWD, look_for_keys=False, **kwargs)
    return cli


def main():
    args = sys.argv[1:]
    if args and args[0] == '-':
        cmd = sys.stdin.read()
    else:
        cmd = ' '.join(args)
    cli = connect()
    try:
        _, so, se = cli.exec_command(cmd, timeout=900)
        out = so.read().decode('utf-8', 'replace')
        err = se.read().decode('utf-8', 'replace')
        rc = so.channel.recv_exit_status()
        if out:
            print(out, end='' if out.endswith('\n') else '\n')
        if err:
            print('[stderr] ' + err.strip(), file=sys.stderr)
        sys.exit(rc)
    finally:
        cli.close()


if __name__ == '__main__':
    main()
