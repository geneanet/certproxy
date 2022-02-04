# -*- coding: utf-8 -*-

import os
import pwd
import grp
import logging

logger = logging.getLogger('certproxy.tools.misc')


def impersonation(user: str=None, group: str=None, workdir: str=None):
    def impersonate():
        """Change user, group and workdir"""
        if group is not None:
            os.setgroups([])
            os.setgid(grp.getgrnam(group).gr_gid)

        if user is not None:
            os.setuid(pwd.getpwnam(user).pw_uid)

        if workdir is not None:
            os.chdir(workdir)

    return impersonate


def print_array(rows: list, headers: list=None):
    if not headers:
        headers = []

    widths = [max(map(len, map(str, col))) for col in zip(headers, *rows)]

    if len(headers):
        print(' '.join([val.ljust(width) for val, width in zip(headers, widths)]))
        print('-' * (sum(widths) + len(widths) - 1))

    for row in rows:
        print(' '.join([str(val).ljust(width) for val, width in zip(row, widths)]))


def readfile(path: str, binary: bool=False):
    if binary:
        mode = 'rb'
    else:
        mode = 'r'

    with open(path, mode) as f:
        return f.read()


def writefile(path: str, data, owner: str=None, group: str=None, mode: int=None):
    if isinstance(data, bytes):
        openmode = 'wb'
    else:
        openmode = 'w'

    if owner is not None:
        uid = pwd.getpwnam(owner).pw_uid
    else:
        uid = -1

    if group is not None:
        gid = grp.getgrnam(group).gr_gid
    else:
        gid = -1

    with open(path, openmode) as f:
        os.fchown(
            f.fileno(),
            uid,
            gid
        )
        if mode is not None:
            os.fchmod(f.fileno(), mode)
        return f.write(data)

def domain_filename(domain: str):
    return domain.replace('*', '_')