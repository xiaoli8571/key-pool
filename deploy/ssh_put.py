"""上传文件：python ssh_put.py 本地1 远程1 [本地2 远程2 ...]"""
import os
import sys

import paramiko

from ssh_config import HOST, KEY, PWD, USER

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
sftp = cli.open_sftp()
try:
    for i in range(0, len(sys.argv) - 1, 2):
        local, remote = sys.argv[1 + i], sys.argv[2 + i]
        sftp.put(local, remote)
        print(f'uploaded {local} -> {remote}')
finally:
    sftp.close()
    cli.close()
