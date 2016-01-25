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
import email
import re
import sys


def labeler(raw_message):
    """
    Apply labels to emails and adjust their flags based on their contents.
    """
    # Convert raw email into an object to make it easier to work with.
    message = email.message_from_string(raw_message)

    # Emails from the CEO get marked urgent and sent to the Inbox.
    if "ceo@big-company.com" in message["from"].lower():
        yield "Urgent"
        yield "Inbox"

    # Emails that look spammy are marked as "read" then sent to Trash.
    elif re.search("V[1i][4a][g9]r[4a]", message["subject"], re.IGNORECASE):
        yield "+Seen"
        yield "Trash"

    # Server alerts are labeled "Pages" and sent to the Inbox.
    elif message["subject"] == "Server Offline":
        yield "Pages"
        yield "Inbox"

    # Alerts for servers coming back online are also labeled as "Pages" but are
    # marked as "read" and not sent to the Inbox.
    elif message["subject"] == "Server Online":
        yield "+Seen"
        yield "Pages"

    # Mark SocialMediaBook birthday emails as "read" and label them "Unwanted
    # Ham."
    elif ("@socialmediabookmail.com" in message["from"] and
      "birthday" in message["subject"].lower()):
        yield "+Seen"
        yield "Unwanted Ham"

    # Returning without yielding any labels or flag changes will cause a
    # message to remain labeled "Unprocessed."


if __name__ == "__main__":
    # Allow the labeler to be run as a stand-alone script. This enables two
    # useful behaviors: first, the script can be tested by simply piping a
    # message into it. Secondly, although this method is less performant, the
    # script can now be invoked once per incoming message which means that the
    # main script need not be restarted if there are changes to the labeler.
    for line in labeler(sys.stdin.read()):
        print(line)
