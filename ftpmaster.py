#!/usr/bin/env python

try:
    from ftpmastersettings import BASE_DIR, LDAP_SERVER, make_ldap_string
except ImportError:
    print('Could not load required data from ftpmastersettings - make sure you have created it as instructed in the README')
    exit(1)

import ldap
import os
import warnings
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

    def validate_authentication(self, username, password):
        """Drop-in for DummyAuthorizer: return True/False of valid login"""
        if _is_anonymous(username):
            return True

        conn = None
        try:
            try:
                conn = ldap.initialize(LDAP_SERVER)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                result = conn.simple_bind_s(make_ldap_string(username), password)
            except ldap.LDAPError, e:
                return False
        finally:
            if conn is not None:
                conn.unbind()

        self.privileged_users.add(username)
        return True

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

        # only privileged users can upload
        if perm not in self.READUPLOAD or username not in self.privileged_users:
            return False

        # don't allow "confusing" zip names
        for name in (UPLOAD, CURRENT, ARCHIVE):
            if path.endswith(os.sep + name + '.zip'):
                return False

        # can only upload zip files
        if os.path.splitext(path)[1].lower() != '.zip':
            return False

        # file must be going into uploads directory
        if os.path.relpath(path, os.path.join(BASE_DIR, UPLOAD))[0] == '.':
            # don't allow file names that begin with '.', and
            # definitely don't allow paths that aren't below BASE_DIR
            return False

        return True

    def get_perms(self, username):
        if username in self.privileged_users:
            return self.READUPLOAD

        return self.READONLY

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
                timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
                archive_path = os.path.join(BASE_DIR, ARCHIVE, main_name, timestamp)
                os.mkdir(archive_path)

                self._safe_extract_all(z, archive_path)

                # delete existing current directory
                current_path = os.path.join(BASE_DIR, CURRENT, main_name)
                if os.path.exists(current_path):
                    rmtree(current_path)
                os.mkdir(current_path)

                self._safe_extract_all(z, current_path)

        os.remove(file)

    def _safe_extract_all(self, zipfile, target_dir):
        """Safer version of ZipFile.extractall -- does not allow absolute or upwards-relative paths"""
        for zipinfo in zipfile.infolist():
            # skip absolute or upwards-relative files
            if zipinfo.filename.startswith(('/', '..')):
                warnings.warn('Skipping potentially unsafe file: ' + zipinfo.filename, RuntimeWarning)
                continue

            # target_dir is base directory; extract will create subpaths as necessary
            zipfile.extract(zipinfo, target_dir)

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
