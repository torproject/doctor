#!/usr/bin/env python
# Copyright 2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Notifies if specific relays reappear in the network.
"""

import datetime
import traceback

import stem.descriptor.remote
import stem.exit_policy
import stem.util.conf

import util

log = util.get_logger('track_relays')

EMAIL_SUBJECT = 'Relays Returned'

EMAIL_BODY = """\
The following previously BadExited relays have returned to the network...

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

    util.send('tracked_relays.cfg entries expired', body = body, to = ['atagar@torproject.org'])

  return results


def main():
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

  downloader = stem.descriptor.remote.DescriptorDownloader()
  found_relays = {}  # mapping of TrackedRelay => RouterStatusEntry

  for desc in downloader.get_consensus():
    if desc.address in tracked_addresses:
      found_relays[tracked_addresses[desc.address]] = desc
    elif desc.fingerprint in tracked_fingerprints:
      found_relays[tracked_fingerprints[desc.fingerprint]] = desc
    else:
      for addr_entry, relay in tracked_address_ranges.items():
        if addr_entry.is_match(desc.address):
          found_relays[relay] = desc

  if found_relays:
    log.debug("Sending a notification for %i relay entries..." % len(found_relays))
    body = EMAIL_BODY

    for tracked_relay, desc in found_relays.items():
      log.debug('* %s' % tracked_relay)
      body += '* %s (%s)\n' % (tracked_relay.identifier, tracked_relay.description)
      body += '  address: %s\n' % desc.address
      body += '  fingerprint: %s\n\n' % desc.fingerprint

    util.send(EMAIL_SUBJECT, body = body, to = ['bad-relays@lists.torproject.org', 'atagar@torproject.org'])


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "track_relays.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
