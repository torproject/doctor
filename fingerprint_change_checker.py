#!/usr/bin/env python
# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Simple script that checks to see if relays rapidly change their finterprint.
This can indicate malicious intent toward hidden services.
"""

import datetime
import time
import traceback

import util

from stem.descriptor.remote import DescriptorDownloader
from stem.util import datetime_to_unix, conf

EMAIL_SUBJECT = 'Relays Changing Fingerprint'

EMAIL_BODY = """\
The following relays are frequently changing their fingerprints...

"""

FINGERPRINT_CHANGES_FILE = util.get_path('data', 'fingerprint_changes')
THIRTY_DAYS = 30 * 24 * 60 * 60

log = util.get_logger('fingerprint_change_checker')


def main():
  fingerprint_changes = load_fingerprint_changes()
  downloader = DescriptorDownloader(timeout = 15)
  alarm_for = set()

  for relay in downloader.get_consensus():
    prior_fingerprints = fingerprint_changes.setdefault((relay.address, relay.or_port), {})

    if relay.fingerprint not in prior_fingerprints:
      log.debug("Registering a new fingerprint for %s:%s (%s)" % (relay.address, relay.or_port, relay.fingerprint))
      prior_fingerprints[relay.fingerprint] = datetime_to_unix(relay.published)

      # drop fingerprint changes that are over thirty days old

      old_fingerprints = [fp for fp in prior_fingerprints if (time.time() - prior_fingerprints[fp] > THIRTY_DAYS)]

      for fp in old_fingerprints:
        log.debug("Removing fingerprint for %s:%s (%s) which was published %i days ago" % (relay.address, relay.or_port, fp, prior_fingerprints[fp] / 60 / 60 / 24))
        del prior_fingerprints[fp]

      # if we've changed more than three times in the last thirty days then alarm

      if len(prior_fingerprints) >= 3:
        alarm_for.add((relay.address, relay.or_port))

  if alarm_for:
    log.debug("Sending a notification for %i relays..." % len(alarm_for))
    body = EMAIL_BODY

    for address, or_port in alarm_for:
      fp_changes = fingerprint_changes[(address, or_port)]
      log.debug("* %s:%s has had %i fingerprints: %s" % (address, or_port, len(fp_changes), ', '.join(fp_changes.keys())))
      body += "* %s:%s\n" % (address, or_port)

      for fingerprint in sorted(fp_changes, reverse = True, key = lambda k: fp_changes[k]):
        body += "  %s at %s\n" % (fingerprint, datetime.datetime.fromtimestamp(fp_changes[fingerprint]).strftime('%Y-%m-%d %H:%M:%S'))

      body += "\n"

    try:
      util.send(EMAIL_SUBJECT, body = body, to = ['atagar@torproject.org'])
    except Exception as exc:
      log.warn("Unable to send email: %s" % exc)

  save_fingerprint_changes(fingerprint_changes)


def load_fingerprint_changes():
  """
  Loads information about prior fingerprint changes we've persisted. This
  provides a dictionary of the form...

    (address, or_port) => {fingerprint: published_timestamp...}
  """

  log.debug("Loading fingerprint changes...")
  config = conf.get_config('fingerprint_changes')

  try:
    config.load(FINGERPRINT_CHANGES_FILE)
    fingerprint_changes = {}

    for key in config.keys():
      address, or_port = key.split(':', 1)

      for value in config.get(key, []):
        fingerprint, published = value.split(':', 1)
        fingerprint_changes.setdefault((address, int(or_port)), {})[fingerprint] = float(published)

    log.debug("  information for %i relays found" % len(fingerprint_changes))
    return fingerprint_changes
  except IOError as exc:
    log.debug("  unable to read '%s': %s" % (FINGERPRINT_CHANGES_FILE, exc))
    return {}


def save_fingerprint_changes(fingerprint_changes):
  log.debug("Saving fingerprint changes for %i relays" % len(fingerprint_changes))
  config = conf.get_config('fingerprint_changes')
  config.clear()

  for address, or_port in fingerprint_changes:
    for fingerprint, published in fingerprint_changes[(address, or_port)].items():
      config.set('%s:%s' % (address, or_port), '%s:%s' % (fingerprint, published), overwrite = False)

  try:
    config.save(FINGERPRINT_CHANGES_FILE)
  except IOError as exc:
    log.debug("  unable to save '%s': %s" % (FINGERPRINT_CHANGES_FILE, exc))


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "fingerprint_change_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
