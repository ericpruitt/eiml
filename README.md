EIML
======

Extended-IMAP Message Labeler (EIML) simplifies programmatic organization of
emails on servers that support Gmail's label extensions. The task of analyzing
and generating labels is farmed out to a user-specified Python module or shell
script while EIML handles applying the changes.

**This is not an official Google product.**

Synopsis
--------

EIML is a script used for organizing emails on Gmail IMAP servers. It downloads
unprocessed messages, feeds them to a labeler and then applies the returned
labels to the emails. The labeler can be a Python function or any program that
can read data from stdin and write to stdout. EIML works with Python 2.7 and
Python 3.2+.

Setup and Configuration
-----------------------

Before running EIML for the first time, please read this section in its
entirety.

### Create Labeler ###

A labeler can be a function defined within a Python script or an arbitrary
subprocess. The raw email passed into Python function will be a "str" in Python
2 and "bytes" in Python 3. In the "examples" folder are two message labeling
scripts that should be useful as a starting point. One script is written in
pure Bash, and the other script is written in Python, but they both process
messages in a similar way.

Python scripts report label assignments by yielding strings whereas
subprocesses report them printing them one per line. If text returned by the
labeler starts with a "+" or "-", the text will be interpreted as an IMAP flag
addition or deletion, respectively instead of a label assignment. IMAP flags
control special properties of messages like whether or not the message is
marked as read; a script that returned "+Seen" as part of its output would
cause a message to be marked "Read." For more information on the flags, refer
to [section 2.3.2 of RFC 3501][rfc-3501-2.3.2]. Once a message is processed, it
is **not** moved to the Inbox by default. A message must explicitly be moved to
the Inbox by the labeler returning the string "Inbox". When no labels are
assigned to a message, the message is ignored in future polling cycles until
EIML is restarted, so it is strongly recommended that labelers always return at
least one label lest the script's memory usage grow indefinitely.

Once a script has been created, it can be tested using the "--dry-run" flag and
the "--source-label"; the "--source-label" flag should be set to whatever label
contains the messages to be used for the dry-run.

  [rfc-3501-2.3.2]: https://tools.ietf.org/html/rfc3501#section-2.3.2

### Launching ###

The basic usage for EIML is `eiml.py [OPTION...] LABELER`. Once the labeler is
written, the way EIML is launched depends on how the script should be executed.
When the labeler is a Python script, `LABELER` is given in the form of
`$PATH_TO_PYTHON_SCRIPT:$FUNCTION_NAME`. For example, if EIML were executed
using the example Python script, the invocation would look like this:

    eiml.py ... examples/python-labeler.py:labeler

If the last argument passed to EIML does not appear to be a Python script and
function, it will be interpreted as a shell script and launched using `$SHELL -c
"$LABELER"`, so launching EIML with the Bash script could look like either of
the following two command assuming the Bash script has the executable bit set:

    eiml.py ... ./examples/bash-labeler.sh
    eiml.py ... "bash -c ./examples/bash-labeler.sh"

When a username is not specified or a password file is not specified, EIML
will prompt for either piece of the login credentials as needed. To learn about
EIML's other features, review the sections below.

### Incoming Message Filter ###

In order for EIML to work properly, a label needs to be applied to all
incoming messages that the script should process. By default, EIML will query
messages labeled "Unprocessed", but this can be changed with the
"--source-label" option. Create a filter for things with the following
properties:

- Doesn't include chats
- Matches all messages with a size greater than 0 bytes

Messages that match the criteria should:

- Skip the Inbox (Archive them)
- Have the label "Unprocessed" (or whatever the is used for "--source-label")
  applied to them

If EIML should not process all messages, adjust the search criteria as
desired. Alternatively, the gmail-filter.xml file in this repository can be
imported into Gmail. For instructions on creating and importing filters, please
read the Gmail help page [Using filters][using-filters].

  [using-filters]: https://support.google.com/mail/answer/6579 "Gmail Help: Using filters"

### Tying it Together ###

Once EIML is configured as desired, create a shell script to launch it with the
necessary parameters. EIML will automatically reconnect to the IMAP server when
it encounters common ephemeral issues, but it may still be a good idea to
automatically relaunch the script if it exits with a return code of 1 for
maximum resilience.

Options
-------

### --auto-archive ###

When specified, all messages in the Inbox that have been read will be archived
at the end of each message processing cycle. When no labeler is specified, this
flag must be set.

### --dry-run  ###

When set, labels returned by the labeler will not applied to messages, and the
"--auto-archive" flag is ignored.

### -h, --help ###

Show script documentation and exit.

### --host=HOST ###

Address of the IMAP host. Host must support Gmail IMAP extensions. Defaults to
"imap.gmail.com".

### --ignore-if-read ###

When specified, unprocessed messages that have already been read will be
ignored.

### --password-file=FILE ###

File containing the password needed to log into the IMAP account.

### --polling-period=NUMBER ###

Number of seconds to wait between polling for and processing messages marked
with label defined with "--source-label". Defaults to 5 seconds.

### --source-label=LABEL ###

Label that contains messages that need to be processed by the script. Defaults
to "Unprocessed".

### --username=EMAIL ###

Email address of the account to access.

### -q ###

Decrease logging verbosity. Can be used repeatedly to further decrease
verbosity.

### -v ###

Increase logging verbosity. Can be used repeatedly to further increase
verbosity.
