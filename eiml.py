#!/usr/bin/env python
# Copyright Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""
Extended-IMAP Message Labeler (EIML) simplifies programmatic organization of
emails on servers that support Gmail's label extensions.

Usage: eiml [OPTION...] LABELER
       eiml --auto-archive [OPTION...]

Options:
 --auto-archive             When specified, all messages in the Inbox that have
                            been read will be archived at the end of each
                            message processing cycle. When no labeler is
                            specified, this flag must be set.

 --dry-run                  When set, labels returned by the labeler will not
                            applied to messages, and the "--auto-archive" flag
                            is ignored.

 -h, --help                 Show this documentation and exit.

 --host=HOST                Address of the IMAP host. Host must support Gmail
                            IMAP extensions. Defaults to "imap.gmail.com".

 --ignore-if-read           When specified, unprocessed messages that have
                            already been read will be ignored.

 --password-file=FILE       File containing the password needed to log into the
                            IMAP account.

 --polling-period=NUMBER    Number of seconds to wait between polling for and
                            processing messages marked with label defined with
                            "--source-label". Defaults to 5 seconds.

 --source-label=LABEL       Label that contains messages that need to be
                            processed by the script. Defaults to "Unprocessed".

 --username=EMAIL           Email address of the account to access.

 -q                         Decrease logging verbosity. Can be used repeatedly
                            to further decrease verbosity.

 -v                         Increase logging verbosity. Can be used repeatedly
                            to further increase verbosity.

The LABELER, which is responsible for assigning labels and updating message
flags, can be specified in two ways: One way is to provide the path to a Python
script followed by a ":" and the function that should be called for labeling
messages. For example, if there is a Python script named `mail-sorter.py`
containing a function `classifier` which is responsible for labeling the
messages, the invocation for EIML would be similar to this:

    eiml ... mail-sorter.py:labeler

The function should accept raw message data as input (for Python 2, the type of
the raw data will be "str" while it will be "bytes" in Python 3) and yield
strings to be applied as labels.

The other way to specify a labeler is with a shell command or script. The
invocation could be something like this:

    eiml ... 'grep -q "^Subject:.*URGENT" && echo Urgent; echo Inbox'

Assuming "./bin/email-sorter" has the executable bit set, a subprocess
invocation could also look like this:

    eiml ... ./bin/email-sorter

The shell used is determined by the `SHELL` environment variable and defaults
to `/bin/sh` when the environment variable is not set.

If no labeler is specified, the "--auto-archive" flag must be specified.

This script will exit with an exit status of 2 if there was a problem during
the initialization phase such as invalid command line options. If an unexpected
error occurs, the script terminates with an exit status of 1.
"""
from __future__ import division, print_function

import email.header
import getopt
import getpass
import imaplib
import imp
import logging
import os
import pipes
import re
import socket
import ssl
import subprocess
import sys
import time

DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
assert DEFAULT_LOG_LEVEL in LOG_LEVELS, "Invalid value for DEFAULT_LOG_LEVEL."

PYTHON_3 = sys.version_info.major > 2

SYSTEM_IMAP_FLAGS = set(
    ("Seen", "Answered", "Flagged", "Deleted", "Draft", "Recent")
)

SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE")
if not SSL_CERT_FILE:
    COMMON_CERT_PATHS = [
        "/etc/ssl/certs/ca-certificates.crt",      # Debian distros and Arch
        "/etc/pki/tls/certs/ca-bundle.crt",        # Red Hat, Fedora and CentOS
        "/usr/local/share/certs/ca-root-nss.crt",  # FreeBSD
        "/etc/ssl/cert.pem",                       # OpenBSD and FreeBSD
    ]
    for path in COMMON_CERT_PATHS:
        if os.path.exists(path):
            SSL_CERT_FILE = path
            break
    else:
        raise Exception(
            "Unable to locate CA certificates. Please set the environment "
            "variable SSL_CERT_FILE to the location of the certificates."
        )

if hasattr(ssl, "PROTOCOL_TLSv1_2"):
    SSL_VERSION = ssl.PROTOCOL_TLSv1_2
elif hasattr(ssl, "PROTOCOL_TLSv1_1"):
    SSL_VERSION = ssl.PROTOCOL_TLSv1_1
elif hasattr(ssl, "PROTOCOL_TLSv1"):
    SSL_VERSION = ssl.PROTOCOL_TLSv1
else:
    raise Exception("SSL library does not appear to have TLS support.")


class Error(Exception):
    """
    Module-specific base-exception.
    """


class NonZeroExitStatus(Error):
    """
    Exception raised when a subprocess returns a non-zero exit status.
    """


class SSLCertificateError(Error):
    """
    Exception raised when there is a problem with a server's SSL certificate.
    """


class IMAPError(Error):
    """
    Exception raised when an IMAP server returns any status other than "OK".
    """


class IMAPCapabilitiesError(Error):
    """
    Exception raised when IMAP server is missing support for a command.
    """


class IMAPConnectionExceptionWrapper(object):
    """
    Class that wraps IMAP connection instances to automatically throw exceptions
    whenever the server returns any status other than "OK".
    """
    def __init__(self, connection):
        self._connection = connection


    def __getattr__(self, name):
        may_be_a_function = attr = getattr(self._connection, name)

        # All of the IMAP4 / IMAP4_SSL attributes that actually matter to the
        # script are callable, so this conditional technically isn't needed.
        if callable(attr):
            def substitute(*args, **kwargs):
                status, data = may_be_a_function(*args, **kwargs)
                if status != "OK":
                    raise IMAPError("IMAP status is '%s': %s" % (status, data))
                return data

            attr = substitute
            setattr(self, name, substitute)

        return attr


class IMAP4ValidatedSSL(imaplib.IMAP4_SSL):
    """
    Class that wraps the IMAP4_SSL class to implement SSL certificate
    validation and is otherwise identical to IMAP4_SSL. If the server
    certificate is invalid, an SSLCertificateError will be raised.
    """
    if PYTHON_3:
        def _create_socket(self):
            """
            Refer to imaplib.IMAP4_SSL._create_socket for documentation.
            """
            unsecured_socket = imaplib.IMAP4._create_socket(self)
            wrapped_socket = ssl.wrap_socket(
                unsecured_socket,
                ca_certs=SSL_CERT_FILE,
                cert_reqs=imaplib.ssl.CERT_REQUIRED,
                ssl_version=SSL_VERSION
            )
            servercert = wrapped_socket.getpeercert()
            match_hostname(servercert, self.host)
            return wrapped_socket

    else:
        def open(self, host="", port=imaplib.IMAP4_SSL_PORT):
            """
            Refer to imaplib.IMAP4_SSL.open for documentation.
            """
            self.host = host
            self.port = port
            self.sock = socket.create_connection((host, port))
            self.sslobj = ssl.wrap_socket(
                self.sock,
                ca_certs=SSL_CERT_FILE,
                cert_reqs=imaplib.ssl.CERT_REQUIRED,
                ssl_version=SSL_VERSION
            )
            servercert = self.sslobj.getpeercert()
            match_hostname(servercert, host)
            self.file = self.sslobj.makefile("rb")


def match_hostname(cert, host):
    """
    Verify that certificate data matches the host. RFC 2818 rules are mostly
    followed, but IP addresses are not accepted for host. An
    SSLCertificateError is raised on failure, and the function returns nothing
    upon success.

    This function is based on Python 2.7.9+ function called "match_hostname" in
    the "ssl" library. The function has been re-implemented to support earlier
    releases of Python 2.7, to provide more verbose errors and to use
    module-specific exception classes declared in this script.
    """
    if not cert:
        raise SSLCertificateError("No server certificate found.")

    def _hostpattern_to_regex(pattern):
        parts = []
        for fragment in pattern.split("."):
            if fragment == "*":
                parts.append("[^.]+")
            else:
                parts.append(re.escape(fragment).replace("\\*", "[^.]*"))

        return re.compile("\\.".join(parts) + "$", re.IGNORECASE)

    dnsnames = []
    altnames = cert.get("subjectAltName", tuple())
    for field, value in altnames:
        if field == "DNS":
            if _hostpattern_to_regex(value).match(host):
                return
            dnsnames.append(value)

    if not altnames:
        for subject in cert.get("subject", tuple()):
            for field, value in subject:
                if field == "commonName":
                    if _hostpattern_to_regex(value).match(host):
                        return
                    dnsnames.append(value)

    if dnsnames:
        msg = "Host '%s' not in list of valid domains: %r" % (host, dnsnames)
    else:
        msg = "No appropriate commonName or subjectAltName fields were found."

    raise SSLCertificateError(msg)


def header_to_string(raw_header):
    """
    Return decoded RFC 2047-encoded email header.
    """
    raw_header = raw_header.decode("latin1")
    header = email.header.make_header(email.header.decode_header(raw_header))
    return str(header) if PYTHON_3 else unicode(header)


def archive_read_messages(connection):
    """
    Archive any messages that have been read.

    Arguments:
      connection: An IMAP connection instance.

    Returns:
      Set containing the UIDs of all archived messages.
    """
    connection.select("Inbox")
    query = "(SEEN)"
    data = connection.uid("SEARCH", None, query)

    if PYTHON_3:
        uids = set(b" ".join(data).decode("ascii").split())
    else:
        uids = set(" ".join(data).split())

    if uids:
        connection.uid("STORE", ",".join(uids), "FLAGS", "\\Deleted")
        uidcount = len(uids)
        schar = "s" if uidcount != 1 else ""
        logging.info("Archived %d message%s: %r", uidcount, schar, uids)
    else:
        logging.debug("No messages in Inbox matching query: %r", query)

    return set(map(int, uids))


def assign_labels(connection, query, labeler, source_label, dry_run=False,
  uidfilter=None):
    """
    Assign labels to messages with the specified `source_label`.

    Arguments:
      connection: An IMAP connection instance.
      query: Parameter used for IMAP search query which determines which
        messages will be enumerated and labeled.
      labeler: Function that accepts the contents of a message as its only
        argument and yields strings that are labels that should be applied to
        the message.
      source_label: Label that contains messages that should be enumerated.
      dry_run: When set, labels returned by the labeler will not actually be
        applied to the messages.
      uidfilter: Function used with the "filter" built-in that accepts a
        message UID as its only argument and returns a boolean value. If the
        returned value is true, the message with the given UID will be
        downloaded and fed into the "labeler" function.

    Returns:
      A set containing UIDs of any messages that did not have labels applied to
      them.
    """
    connection.select(source_label)
    data = connection.uid("SEARCH", None, query)
    uids = set(b" ".join(data).split())

    # A log entry saying 0 messages were processed is pretty useless, so the
    # logging level is decreased when there's nothing for this function to do.
    _logging = logging.info if uids else logging.debug
    uidcount = len(uids)
    schar = "s" if uidcount != 1 else ""
    _logging("Query returned %d message%s: %r", uidcount, schar, query)

    if not uids:
        return set()

    unlabeled_uids = set()
    count = 0
    for count, uid in enumerate(filter(uidfilter, sorted(uids, key=int)), 1):
        uid = uid.decode("ascii")

        # (BODY.PEEK[]) fetches the message without marking it SEEN.
        logging.info("Fetching message: %s", uid)
        response = connection.uid("FETCH", uid, "(BODY.PEEK[])")

        if not response[0]:
            logging.warn("No message data returned by server.")
            continue

        had_label = False
        message = response[0][1]
        move_to_inbox = False
        kib = len(message) / 1024

        try:
            # Using simple substring searching so processing time isn't
            # wasted parsing an entire RFC822 message just to get one
            # line from the header that is only ever used for logging
            # purposes.
            start_of_subject = message.index(b"\nSubject:") + 9
            end_of_subject = message.index(b"\n", start_of_subject + 1)
            subject = message[start_of_subject:end_of_subject].strip()
            if subject:
                subject = header_to_string(subject)
            else:
                subject = "(empty subject)"
        except ValueError:
            subject = "(subject could not be parsed)"

        logging.info("Retrieved %.1fKiB message: %s", kib, subject)

        for label in labeler(message):
            label = label.strip()
            assert label, "Label must not be empty."

            had_label = True
            logging.info("Label or flag change: %r", label)

            # "Labels" starting with "+" or "-" are should be treated as
            # flag assignments.
            if label.startswith(("+", "-")):
                sign = label[0]
                flag = label[1:]
                assert flag, "No flag specified after '" + sign + "'."

                # Not sure if case sensitivity matters with IMAP flags, but
                # the RFC has all system flags in title-case.
                normalized_flag = flag.capitalize()
                if normalized_flag in SYSTEM_IMAP_FLAGS:
                    flag = "\\" + normalized_flag

                if not dry_run:
                    connection.uid("STORE", uid, sign + "FLAGS", flag)

            # The inbox requires special treatment, so inbox assignment is
            # handled after all normal label assignments. Also has the
            # added benefit of ensuring a message's labels are visible
            # before the end-user sees the message.
            elif label.upper() == "INBOX":
                move_to_inbox = True

            # Use Gmail"s IMAP extension to assign labels to messages.
            elif not dry_run:
                connection.uid("STORE", uid, "+X-GM-LABELS", label)

        if had_label:
            if dry_run:
                unlabeled_uids.add(uid)

            else:
                if move_to_inbox:
                    connection.uid("COPY", uid, "INBOX")

                # Marking a message "Deleted" while having a label SELECT-ed
                # simply removes the SELECT-ed label from that message.
                connection.uid("STORE", uid, "FLAGS", "\\Deleted")

            logging.info("Done labeling message.")

        else:
            # Messages that were not tagged by the classifier should be
            # unlabeled_messages in subsequent iterations.
            logging.warn("Labeler did not assign any labels to message.")
            unlabeled_uids.add(uid)

    logging.info("Finished processing messages: %d", count)
    return unlabeled_uids


def main(username, password, labeler=None, source_label="Unprocessed",
 polling_period=5, ignore_if_read=False, auto_archive=False,
  host="imap.gmail.com", dry_run=False):
    """
    Poll and organize messages in a Gmail account.

    Arguments:
      username: IMAP username. For Gmail, this is the full email address that
        includes the username and fully-qualified domain name.
      password: IMAP password.
      labeler: Function that accepts the contents of a message as its only
        argument and yields strings that are labels that should be applied to
        the message.
      ignore_if_read: When specified, unprocessed messages that have already
        been read will be ignored.
      source_label: Label that contains messages that should be enumerated for
        labeling.
    """
    connection = IMAP4ValidatedSSL(host)
    connection = IMAPConnectionExceptionWrapper(connection)
    connection.login(username, password)

    if PYTHON_3:
        chunk = b" ".join(connection.capability()).decode("ascii")
    else:
        chunk = " ".join(connection.capability())

    capabilities = set(chunk.split())
    logging.debug("Mail server capabilities: %r", capabilities)
    if "X-GM-EXT-1" not in capabilities:
        raise IMAPCapabilitiesError("The server lacks Gmail IMAP extensions.")

    query = "(UNSEEN)" if ignore_if_read else "ALL"
    unlabeled_uids = set()
    uidfilter = lambda uid: uid not in unlabeled_uids

    if dry_run and auto_archive:
        auto_archive = False
        logging.warn("Auto-archive does nothing in dry-run mode.")

    while True:
        if labeler:
            unlabeled_uids.update(
              assign_labels(
                connection,
                query,
                labeler,
                source_label,
                dry_run,
                uidfilter
              )
            )

        if auto_archive:
            archive_read_messages(connection)

        logging.debug("Sleep duration: %r", polling_period)
        time.sleep(polling_period)


def labels_from_subprocess(argv):
    """
    Function used to tag a message using a subprocess.

    The message is piped into the subprocess and, provided the subprocess did
    not exit with a non-zero exit status, each line emitted by the subprocess
    is yielded. Blank lines are ignored, and leading and trailing whitespace is
    trimmed.

    Arguments:
      argv: Arguments of command to launch

    Returns:
      Function that can be used as the "labeler" argument of `main` and
      `assign_labels`.
    """
    def subprocess_labeler(message):
        logging.debug("Launching subprocess: %r", argv)
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(message)
        failure = proc.wait()

        if failure:
            labeler = " ".join(map(pipes.quote, argv))
            message = "$(%s) exited with status of %d" % (labeler, failure)
            stderr = stderr.strip()
            if stderr:
                message += ": " + stderr.decode("utf-8", errors="replace")

            raise NonZeroExitStatus(message)

        for line in stdout.splitlines():
            line = line.strip()
            if line:
                yield line

    subprocess_labeler.__doc__ = "argv = " + repr(argv)
    return subprocess_labeler


def options_from_argv(argv, allow_log_level_change=True):
    """
    Parse command line arguments and convert them into a dictionary that can be
    used to pass keyword arguments into `main`.

    Arguments:
      argv: Arguments to be parsed. This should typically be sys.argv[1:].
      allow_log_level_change: When this is `True`, executing this function may
        result in the global log level being changed. Setting this flag to
        `False` makes this function idempotent.

    Returns:
      Dictionary that can be used to set keyword arguments of `main` function.
    """
    longopts = [
        "auto-archive",
        "dry-run",
        "help",
        "host=",
        "ignore-if-read",
        "password-file=",
        "polling-period=",
        "source-label=",
        "username=",
    ]
    opts, tail = getopt.gnu_getopt(argv, "hvq", longopts=longopts)

    if ("--help", "") in opts or ("-h", "") in opts:
        # Module doc string is the usage string.
        print(__doc__.strip("\r\n"))
        sys.exit(2 if len(opts) != 1 else 0)

    else:
        # Set logging verbosity based on number of -q and -v flags.
        delta = opts.count(("-q", "")) - opts.count(("-v", ""))
        log_level = LOG_LEVELS.index(DEFAULT_LOG_LEVEL)
        log_level = max(0, min(len(LOG_LEVELS) - 1, log_level + delta))
        if allow_log_level_change:
            level_number = getattr(logging, LOG_LEVELS[log_level])
            logging.getLogger().setLevel(level_number)
        logging.debug("Logging set: %r", LOG_LEVELS[log_level])

        # Most command line options correspond to keyword arguments of "main",
        # so the dashes must be changed to underscores and any trailing
        # underscores stripped.
        options = dict(((k.replace("-", "_").strip("_"), v) for k, v in opts))

        # Not valid keywords for main function.
        options.pop("v", None)
        options.pop("q", None)

    if len(tail) == 1:
        options["labeler"] = tail[0]
    elif tail:
        extra_args = " ".join(map(pipes.quote, tail[1:]))
        raise Error("Unexpected arguments: %s" % (extra_args,))
    elif "auto_archive" not in options:
        raise Error("If no labeler is specified, --auto-archive must be set.")

    try:
        options["polling_period"] = float(options["polling_period"])
    except KeyError:
        pass
    except ValueError:
        raise Error("Invalid polling period: %s" % (options["polling_period"]))
    else:
        if options["polling_period"] < 0:
            raise ValueError("Polling period must be at least 0.")

    try:
        with open(options.pop("password_file")) as iostream:
            options["password"] = iostream.read().rstrip("\r\n")
    except KeyError:
        options["password"] = getpass.getpass()

    if "username" not in options:
        options["username"] = raw_input("Email address: ").strip()

    if "labeler" in options:
        labeler = options["labeler"]
        labelerfn = None
        if ":" in labeler:
            path, function_name = labeler.rsplit(":", 1)
            if os.path.exists(path):
                module_dir = os.path.dirname(path)
                if module_dir not in sys.path:
                    sys.path.append(module_dir)
                module = imp.load_source("labeler_module", path)
                labelerfn = getattr(module, function_name)
                logging.info("Found object: (%r, %r)", path, function_name)
                if callable(labelerfn):
                    options["labeler"] = labelerfn
                else:
                    raise TypeError("%s in %r: not callable." % (function, path))
            else:
                logging.warning("%r: file not found", path)

        if not labelerfn:
            if os.path.exists(labeler):
                argv = [labeler]
            else:
                shell = os.environ.get("SHELL", "/bin/sh")
                argv = [shell, "-c", labeler]

            shell_script = " ".join(map(pipes.quote, argv))
            logging.info("Labeler command: %s", shell_script)
            options["labeler"] = labels_from_subprocess(argv)

    options["auto_archive"] = "auto_archive" in options
    options["dry_run"] = "dry_run" in options
    options["ignore_if_read"] = "ignore_if_read" in options
    return options


if __name__ == "__main__":
    try:
        logging.basicConfig(
            format="%(asctime)s <%(levelname)s> %(funcName)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

        failure_status = 2
        options = options_from_argv(sys.argv[1:])
        failure_status = 1

        if options.get("dry_run"):
            logging.warn("This is a dry run; no changes will be applied.")

        # Remove password from logging output.
        options_censored = dict(options)
        options_censored["password"] = "<censored>"
        arguments = ("%s=%r" % (k, v) for k, v in options_censored.items())

        while True:
            try:
                logging.debug("main(%s)", ", ".join(arguments))
                main(**options)
            except imaplib.IMAP4.readonly:
                raise
            except imaplib.IMAP4.abort as exc:
                # Per the imaplib documentation, applications should simply
                # reconnect after encountering imaplib.IMAP4.abort errors.
                logging.critical("Connection aborted: %s", exc)

    except Exception as exc:
        # Make the error message a tad more user-friendly before displaying it.
        if isinstance(exc, imaplib.IMAP4.error):
            cls = "IMAPError"
        else:
            cls = exc.__class__.__name__

        # Regex from http://stackoverflow.com/a/12867228; thanks Nick Lombard.
        error = re.sub("((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))", " \\1", cls)
        if isinstance(exc, Error):
            # The "critical" method is used here because the error
            # module-specific exceptions raised by the script should be
            # resolvable without a stack trace; logging.exception outputs the
            # stack trace in addition to the stringified error.
            logging.critical("%s: %s", error.replace("Exception", "Error"), exc)
        else:
            logging.exception("%s: %s", error.replace("Exception", "Error"), exc)

        sys.exit(failure_status)

