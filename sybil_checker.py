#!/usr/bin/env python
# Copyright 2013 The Tor Project
# See LICENSE for licensing information

"""
Simple script that checks to see if there has been a sudden influx of new
relays. If so then this sends an email notification.
"""

import os
import traceback

import util

from stem.descriptor.remote import DescriptorDownloader

EMAIL_SUBJECT = 'Possible Sybil Attack'

EMAIL_BODY = """\
Over the last hour %i new relays have appeared. New additions are...

"""

RELAY_ENTRY = """\
* %s (%s)
  Address: %s:%i
  Version: %s
  Exit Policy: %s
"""

FINGERPRINTS_FILE = util.get_path('data', 'fingerprints')

log = util.get_logger('sybil_checker')


def main():
  prior_fingerprints = load_fingerprints()
  downloader = DescriptorDownloader(timeout = 60)

  if not prior_fingerprints:
    log.debug("We don't have any existing fingerprints so this will be a dry-run. No notifications will be sent.")

  query = downloader.get_consensus()
  query.run(True)

  if query.error:
    log.warn("Unable to retrieve the consensus: %s" % query.error)
    return

  # mapping of fingerprints to their router status entry
  relays = dict((entry.fingerprint, entry) for entry in query)

  current_fingerprints = set(relays.keys())
  new_fingerprints = current_fingerprints.difference(prior_fingerprints)
  log.debug("%i new relays found" % len(new_fingerprints))

  if prior_fingerprints and len(new_fingerprints) >= 50:
    log.debug("Sending a notification...")
    send_email([relays[fp] for fp in new_fingerprints])

  save_fingerprints(prior_fingerprints.union(current_fingerprints))


def send_email(new_relays):
  # constructs a mapping of nicknames to router status entries so we can provide a listing that's sorted by nicknames

  nickname_to_relay = dict((entry.nickname, entry) for entry in new_relays)
  relay_entries = []

  for nickname in sorted(nickname_to_relay.keys()):
    relay = nickname_to_relay[nickname]
    relay_entries.append(RELAY_ENTRY % (relay.nickname, relay.fingerprint, relay.address, relay.or_port, relay.version, relay.exit_policy))

  try:
    body = EMAIL_BODY % len(new_relays)
    body += "\n".join(relay_entries)

    util.send(EMAIL_SUBJECT, body_text = body)
  except Exception, exc:
    log.warn("Unable to send email: %s" % exc)


def load_fingerprints():
  log.debug("Loading fingerprints...")

  if not os.path.exists(FINGERPRINTS_FILE):
    log.debug("  '%s' doesn't exist" % FINGERPRINTS_FILE)
    return set()

  try:
    with open(FINGERPRINTS_FILE) as fingerprint_file:
      fingerprints = fingerprint_file.read().strip()

      if not fingerprints:
        log.debug("  '%s' is empty" % FINGERPRINTS_FILE)
        return set()

      fingerprints = fingerprints.splitlines()

      log.debug("  %i fingerprints found" % len(fingerprints))
      return set(fingerprints)
  except Exception, exc:
    log.debug("  unable to read '%s': %s" % (FINGERPRINTS_FILE, exc))
    return set()


def save_fingerprints(fingerprints):
  data_dir = util.get_path('data')

  try:
    if not os.path.exists(data_dir):
      os.mkdir(data_dir)

    with open(FINGERPRINTS_FILE, 'w') as fingerprint_file:
      fingerprint_file.write('\n'.join(fingerprints))
  except Exception, exc:
    log.debug("Unable to save fingerprints to '%s': %s" % (FINGERPRINTS_FILE, exc))


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "sybil_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body_text = msg)
