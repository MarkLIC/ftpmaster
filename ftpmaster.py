#!/usr/bin/env python

"""
ftpmaster is available under the MIT License:

Copyright (c) 2011 Mark Rushakoff, Lafayette Instrument Company

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

try:
    from ftpmastersettings import BASE_DIR, LDAP_SERVER, make_ldap_string, UPLOADERS, \
      LISTEN_IP, LISTEN_PORT, LOG_DIR
except ImportError:
    print('Could not load required data from ftpmastersettings - make sure you have created it as instructed in the README')
    exit(1)

import ldap
import logging
import logging.handlers
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
        if perm not in self.READUPLOAD or username not in UPLOADERS:
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
        if username in UPLOADERS:
            return self.READUPLOAD

        return self.READONLY

    def get_home_dir(self, username):
        """ All users have the same home directory"""
        return BASE_DIR

    def get_msg_login(self, username):
        if _is_anonymous(username):
            return "Welcome anonymous user"

        if username in UPLOADERS:
            return "Welcome " + username + "!  You have upload privileges."

        return "Welcome " + username

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
                timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S+" + self.username)
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

# Default handler goes to stderr.  File handlers added after this.
logging.basicConfig(format='%(asctime)s %(message)s')

_normal_log = logging.getLogger('ftpmaster_normal')
_normal_log.setLevel(logging.DEBUG)
_normal_log.addHandler(logging.handlers.TimedRotatingFileHandler(os.path.join(LOG_DIR, 'ftp_normal.log'), when='d', backupCount=5))

_line_log = logging.getLogger('ftpmaster_line')
_line_log.setLevel(logging.DEBUG)
_line_log.addHandler(logging.handlers.TimedRotatingFileHandler(os.path.join(LOG_DIR, 'ftp_line.log'), when='h', interval=6, backupCount=12))

_error_log = logging.getLogger('ftpmaster_error')
_error_log.setLevel(logging.WARNING)
_line_log.addHandler(logging.handlers.TimedRotatingFileHandler(os.path.join(LOG_DIR, 'ftp_error.log'), when='d', interval=7, backupCount=52))

def log_normal(msg):
    _normal_log.info(msg)

def log_line(msg):
    _line_log.info(msg)

def log_error(msg):
    _error_log.error(msg)

def main():
    ftpserver.log = log_normal
    ftpserver.logline = log_line
    ftpserver.logerror = log_error

    make_default_dirs()

    handler = UnzippingHandler
    handler.authorizer = LdapAuthorizer()

    address = (LISTEN_IP, LISTEN_PORT)
    server = ftpserver.FTPServer(address, handler)

    server.max_cons = 256
    server.max_cons_per_ip = 5

    server.serve_forever()

if __name__ == "__main__":
    main()
