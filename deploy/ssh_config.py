"""SSH 连接参数：优先环境变量，其次 deploy/ssh.env（KEY=VALUE，gitignore 排除），都没有则报错。

支持密钥认证：设置 KP_SSH_KEY 指向私钥文件即可（与密码二选一）。
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_env_file():
    path = os.path.join(_HERE, 'ssh.env')
    if not os.path.isfile(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _get(name, required=True, default=''):
    _load_env_file()
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(
            f'缺少 {name}：请设置环境变量，或在 deploy/ssh.env 写一行 {name}=...（该文件已被 .gitignore 排除）'
        )
    return val


HOST = _get('KP_SSH_HOST')
USER = _get('KP_SSH_USER', default='root')
KEY = os.environ.get('KP_SSH_KEY', '')
PWD = _get('KP_SSH_PWD', required=not KEY)
