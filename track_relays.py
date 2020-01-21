#!/usr/bin/env python
# Copyright 2016-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Notifies if specific relays reappear in the network.
"""

import datetime
import os
import time
import traceback

import stem.descriptor.remote
import stem.exit_policy
import stem.util.conf

import util

log = util.get_logger('track_relays')

EMAIL_SUBJECT = 'Relays Returned'
ONE_WEEK = 7 * 24 * 60 * 60

EMAIL_BODY = """\
The following previously relays flagged as being malicious have returned to the
network...

"""


class TrackedRelay(object):
  """
  Represents a relay we're keeping an eye on.

  :var str identifier: brief identifier given to the entry
  :var str description: description of why we're tracking it
  :var datetime expires: when this entry expires
  :var list addresses: address of the relay we're tracking
  :var list fingerprints: fingerprint of the relay we're tracking
  """

  def __init__(self, identifier, config):
    self.identifier = identifier
    self.description = config.get('%s.description' % identifier, '')

    expires_str = config.get('%s.expires' % identifier, '')

    if not expires_str:
      raise ValueError("Our config file is missing a '%s.expires' entry" % identifier)

    try:
      self.expires = datetime.datetime.strptime(expires_str, '%Y-%m-%d')
    except ValueError:
      raise ValueError("'%s.expires' is malformed. We expect it to be in the form 'Year-Month-Day'" % identifier)

    self.addresses = config.get('%s.address' % identifier, [])
    self.fingerprints = config.get('%s.fingerprint' % identifier, [])

    if not self.addresses and not self.fingerprints:
      raise ValueError("We need either a '%s.address' or '%s.fingerprint' to track" % (identifier, identifier))

  def __str__(self):
    attr = []

    for address in self.addresses:
      attr.append('address: %s' % address)

    for fingerprint in self.fingerprints:
      attr.append('fingerprint: %s' % fingerprint)

    return '%s (%s)' % (self.identifier, ', '.join(attr))


def get_tracked_relays():
  """
  Provides the relays we're tracking.

  :returns: **list** of **TrackedRelay** we're tracking

  :raises: **ValueError** if our config file is malformed
  """

  config = stem.util.conf.get_config('tracked_relays')
  config.load(util.get_path('data', 'tracked_relays.cfg'))

  results, expired = [], []

  for identifier in set([key.split('.')[0] for key in config.keys()]):
    relay = TrackedRelay(identifier, config)

    if relay.expires > datetime.datetime.now():
      results.append(relay)
    else:
      expired.append(relay)

  if expired:
    body = 'The following entries in tracked_relays.cfg have expired...\n\n'

    for relay in expired:
      body += '* %s (%s)\n' % (relay.identifier, relay.expires.strftime('%Y-%m-%d'))

    util.send('tracked_relays.cfg entries expired', body = body, to = ['gk@torproject.org'])

  return results


def main():
  last_notified_config = stem.util.conf.get_config('last_notified')
  last_notified_path = util.get_path('data', 'track_relays_last_notified.cfg')

  if os.path.exists(last_notified_path):
    last_notified_config.load(last_notified_path)
  else:
    last_notified_config._path = last_notified_path

  # Map addresses and fingerprints to relays for constant time lookups. Address
  # ranges are handled separately cuz... well, they're a pita.

  tracked_addresses = {}
  tracked_address_ranges = {}
  tracked_fingerprints = {}

  for relay in get_tracked_relays():
    for address in relay.addresses:
      if '/' in address:
        # It's a total hack, but taking advantage of exit policies where we
        # already support address ranges.

        tracked_address_ranges[stem.exit_policy.ExitPolicyRule('accept %s:*' % address)] = relay
      else:
        tracked_addresses[address] = relay

    for fingerprint in relay.fingerprints:
      tracked_fingerprints[fingerprint] = relay

  found_relays = {}  # mapping of TrackedRelay => RouterStatusEntry

  for desc in stem.descriptor.remote.get_consensus():
    if desc.address in tracked_addresses:
      found_relays.setdefault(tracked_addresses[desc.address], []).append(desc)
    elif desc.fingerprint in tracked_fingerprints:
      found_relays.setdefault(tracked_fingerprints[desc.fingerprint], []).append(desc)
    else:
      for addr_entry, relay in tracked_address_ranges.items():
        if addr_entry.is_match(desc.address):
          found_relays.setdefault(relay, []).append(desc)

  all_descriptors = []

  for relays in found_relays.values():
    all_descriptors += relays

  if found_relays and not is_notification_suppressed(all_descriptors):
    log.debug("Sending a notification for %i relay entries..." % len(found_relays))
    current_time = str(int(time.time()))
    body = EMAIL_BODY

    for tracked_relay, relays in found_relays.items():
      log.debug('* %s' % tracked_relay)
      body += '* %s (%s)\n' % (tracked_relay.identifier, tracked_relay.description)

      for desc in relays:
        body += '  address: %s:%s, fingerprint: %s\n' % (desc.address, desc.or_port, desc.fingerprint)
        last_notified_config.set('%s:%s' % (desc.address, desc.or_port), current_time)

    util.send(EMAIL_SUBJECT, body = body, to = ['bad-relays@lists.torproject.org', 'gk@torproject.org'])
    last_notified_config.save()


def is_notification_suppressed(relays):
  """
  Check to see if we've already notified for all these relays today. No
  point in causing too much noise.
  """

  is_all_suppressed = True
  log.debug("Checking if notification should be suppressed...")
  last_notified_config = stem.util.conf.get_config('last_notified')

  for desc in relays:
    key = '%s:%s' % (desc.address, desc.or_port)
    suppression_time = ONE_WEEK - (int(time.time()) - last_notified_config.get(key, 0))

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
    msg = "track_relays.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
