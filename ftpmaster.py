#!/usr/bin/env python

try:
    from ftpmastersettings import BASE_DIR
except ImportError:
    print('Could not load settings from ftpmastersettings - make sure you have created it as instructed in the README')
    exit(1)

import os
import zipfile
from pyftpdlib import ftpserver
from datetime import datetime
from shutil import rmtree

ARCHIVE = 'archive'
CURRENT = 'current'
UPLOAD = 'upload'

def _is_anonymous(username):
    return username == 'anonymous'

class LdapAuthorizer(object):
    READONLY = 'elr'
    READUPLOAD = 'elrw'

    def __init__(self):
        self.privileged_users = set()

        # TODO: only add after validate_authentication
        self.privileged_users.add('test')

    def validate_authentication(self, username, password):
        """Drop-in for DummyAuthorizer: return True/False of valid login"""
        if _is_anonymous(username):
            return True

        # TODO: validate against actual LDAP
        return username == 'test' and password == 'test'

    def impersonate_user(self, username, password):
        # This would involve actual OS permissions, so we don't care
        pass

    def terminate_impersonation(self, username):
        # This would involve actual OS permissions, so we don't care
        pass

    def has_perm(self, username, perm, path=None):
        """ Path is the full OS path of the target file"""
        if perm in self.READONLY:
            return True

        return perm in self.READUPLOAD and username in self.privileged_users

    def get_perms(self, username):
        if _is_anonymous(username):
            return self.READONLY

        return self.READUPLOAD

    def get_home_dir(self, username):
        """ All users have the same home directory"""
        return BASE_DIR

    def get_msg_login(self, username):
        if _is_anonymous(username):
            return "Welcome anonymous user"

        # TODO: give a better message, based on username?
        return "Welcome privileged user"

    def get_msg_quit(self, username):
        return "Goodbye"

class UnzippingHandler(ftpserver.FTPHandler):
    def on_file_received(self, file):
        """file is the absolute name of the file just being received"""

        if zipfile.is_zipfile(file):
            filename = os.path.basename(file)
            main_name = os.path.splitext(filename)[0]

            # make a missing archive folder
            subfolder_path = os.path.join(BASE_DIR, ARCHIVE, main_name)
            if not os.path.exists(subfolder_path):
                os.mkdir(subfolder_path)

            with zipfile.ZipFile(file, 'r') as z:
                # extract to archive dir first, so as to not overwrite anything
                # TODO: append user id to timestamp
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                archive_path = os.path.join(BASE_DIR, ARCHIVE, main_name, timestamp)
                os.mkdir(archive_path)

                # TODO: Verify warning as explained in extractall docs
                z.extractall(archive_path)

                # delete existing current directory
                current_path = os.path.join(BASE_DIR, CURRENT, main_name)
                if os.path.exists(current_path):
                    rmtree(current_path)
                os.mkdir(current_path)

                # TODO: Verify warning as explained in extractall docs
                z.extractall(current_path)

        os.remove(file)

def make_default_dirs():
    for subfolder in (ARCHIVE, CURRENT, UPLOAD):
        subfolder_path = os.path.join(BASE_DIR, subfolder)
        if not os.path.exists(subfolder_path):
            os.mkdir(subfolder_path)

def main():
    make_default_dirs()

    handler = UnzippingHandler
    handler.authorizer = LdapAuthorizer()

    address = ('127.0.0.1', 21)
    server = ftpserver.FTPServer(address, handler)

    server.max_cons = 256
    server.max_cons_per_ip = 5

    server.serve_forever()

if __name__ == "__main__":
    main()
