#!/usr/bin/env bash
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

# Exit on any uncaught errors and upon encountering undefined variables, and
# make regular expressions case insensitive.
shopt -s errexit nounset nocasematch

main() {
    local flags
    local line

    flags=""
    while read line; do
        # Emails from the CEO get marked urgent and sent to the Inbox.
        if [[ "$line" =~ ^From:.*ceo@big-company.com ]]; then
            echo "Urgent"
            echo "Inbox"
            break

        # Emails that look spammy are marked as "read" then sent to Trash.
        elif [[ "$line" =~ ^Subject:.*V[1i][4a][g9]r[4a] ]]; then
            echo "+Seen"
            echo "Inbox"
            break

        # Server alerts are labeled "Pages" and sent to the Inbox.
        elif [[ "$line" =~ ^Subject:\ Server\ Offline ]]; then
            echo "Pages"
            echo "Inbox"
            break

        # Alerts for servers coming back online are also labeled as "Pages" but
        # are marked as "read" and not sent to the Inbox.
        elif [[ "$line" =~ ^Subject:\ Server\ Online ]]; then
            echo "+Seen"
            echo "Pages"
            break

        # Add a flag for emails from SocialMediaBook
        elif [[ "$line" =~ ^From:.*@socialmediabookmail.com ]]; then
            flags="$flags fbmsg"

        # Add a flag for emails containing "birthday" in the subject.
        elif [[ "$line" =~ ^Subject:.*birthday ]]; then
            flags="$flags birthday"
        fi

        # Mark SocialMediaBook emails with "birthday" in the subject as "read"
        # and label them "Unwanted Ham."
        if [[ "$flags" = *birthday* ]] && [[ "$flags" = *fbmsg* ]]; then
            echo "+Seen"
            echo "Unwanted Ham"
            break
        fi
    done

    # Exiting without printing any labels or flag changes will cause a message
    # to remain unread and labeled "Unprocessed."
}

# Allow passing "-v" to enable Bash debugging.
if [[ "${1:-}" = "-v" ]]; then
    shift
    echo "Bash debug mode enabled." >&2
    set -x
fi

main "$@"
