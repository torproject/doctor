#!/usr/bin/env python
# Copyright 2015-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Simple script that checks to see if relays rapidly change their finterprint.
This can indicate malicious intent toward hidden services.
"""

import datetime
import os
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
ONE_DAY = 24 * 60 * 60
TEN_DAYS = 10 * 24 * 60 * 60

log = util.get_logger('fingerprint_change_checker')


def main():
  last_notified_config = conf.get_config('last_notified')
  last_notified_path = util.get_path('data', 'fingerprint_change_last_notified.cfg')

  if os.path.exists(last_notified_path):
    last_notified_config.load(last_notified_path)
  else:
    last_notified_config._path = last_notified_path

  fingerprint_changes = load_fingerprint_changes()
  downloader = DescriptorDownloader(timeout = 15)
  alarm_for = {}

  for relay in downloader.get_consensus():
    prior_fingerprints = fingerprint_changes.setdefault((relay.address, relay.or_port), {})

    if relay.fingerprint not in prior_fingerprints:
      log.debug("Registering a new fingerprint for %s:%s (%s)" % (relay.address, relay.or_port, relay.fingerprint))
      prior_fingerprints[relay.fingerprint] = datetime_to_unix(relay.published)

      # drop fingerprint changes that are over thirty days old

      old_fingerprints = [fp for fp in prior_fingerprints if (time.time() - prior_fingerprints[fp] > TEN_DAYS)]

      for fp in old_fingerprints:
        log.debug("Removing fingerprint for %s:%s (%s) which was published %i days ago" % (relay.address, relay.or_port, fp, prior_fingerprints[fp] / 60 / 60 / 24))
        del prior_fingerprints[fp]

      # if we've changed more than ten times in the last ten days then alarm

      if len(prior_fingerprints) >= 10:
        alarm_for['%s:%s' % (relay.address, relay.or_port)] = (relay.address, relay.or_port, relay.fingerprint)

  if alarm_for and not is_notification_suppressed(alarm_for.values()):
    log.debug("Sending a notification for %i relays..." % len(alarm_for))
    body = EMAIL_BODY

    for address, or_port, fingerprint in alarm_for.values():
      try:
        desc = downloader.get_server_descriptors(fingerprint).run()[0]
      except:
        desc = None  # might not be available, just used for extra info

      fp_changes = fingerprint_changes[(address, or_port)]
      log.debug("* %s:%s has had %i fingerprints: %s" % (address, or_port, len(fp_changes), ', '.join(fp_changes.keys())))

      if desc:
        body += "* %s:%s (platform: %s, contact: %s)\n" % (address, or_port, desc.platform.decode('utf-8', 'replace'), desc.contact)
      else:
        body += "* %s:%s\n" % (address, or_port)

      count = 0

      for fingerprint in sorted(fp_changes, reverse = True, key = lambda k: fp_changes[k]):
        body += "  %s at %s\n" % (fingerprint, datetime.datetime.fromtimestamp(fp_changes[fingerprint]).strftime('%Y-%m-%d %H:%M:%S'))
        count += 1

        # Relays frequently cycling their fringerprint can have thousands of
        # entries. Enumerating them all is unimportant, so if too long then
        # just give the count.

        if count > 8:
          oldest_timestamp = sorted(fp_changes.values())[0]
          body += "  ... and %i more since %s\n" % (len(fp_changes) - 8, datetime.datetime.fromtimestamp(oldest_timestamp).strftime('%Y-%m-%d %H:%M:%S'))
          break

      body += "\n"

    subject = EMAIL_SUBJECT

    if len(alarm_for) == 1:
      subject += ' (%s:%s)' % alarm_for.values()[0][:2]

    util.send(subject, body = body, to = ['tor-network-alerts@lists.torproject.org', 'gk@torproject.org'])

    # register that we've notified for these

    current_time = str(int(time.time()))

    for address, or_port, _ in alarm_for.values():
      last_notified_config.set('%s:%s' % (address, or_port), current_time)

    last_notified_config.save()

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


def is_notification_suppressed(fingerprint_changes):
  """
  Check to see if we've already notified for all these endpoints today. No
  point in causing too much noise.
  """

  is_all_suppressed = True
  log.debug("Checking if notification should be suppressed...")
  last_notified_config = conf.get_config('last_notified')

  for address, or_port, _ in fingerprint_changes:
    key = '%s:%s' % (address, or_port)
    suppression_time = ONE_DAY - (int(time.time()) - last_notified_config.get(key, 0))

    if suppression_time < 0:
      log.debug("* notification for %s isn't suppressed" % key)
      is_all_suppressed = False
    else:
      log.debug("* we already notified for %s recently, suppressed for %i hours" % (key, suppression_time / 3600))

  return is_all_suppressed


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "fingerprint_change_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
