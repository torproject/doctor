#!/usr/bin/env python
# Copyright 2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Notifies if specific relays reappear in the network.
"""

import datetime
import traceback

import stem.descriptor.remote
import stem.util.conf

import util

log = util.get_logger('track_relays')

EMAIL_SUBJECT = 'Relays Returned'

EMAIL_BODY = """\
The following previously BadExit relays have returned to the network...

"""


class TrackedRelay(object):
  """
  Represents a relay we're keeping an eye on.

  :var str identifier: brief identifier given to the entry
  :var str description: description of why we're tracking it
  :var datetime expires: when this entry expires
  :var str address: address of the relay we're tracking
  :var str fingerprint: fingerprint of the relay we're tracking
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

    self.address = config.get('%s.address' % identifier, None)
    self.fingerprint = config.get('%s.fingerprint' % identifier, None)

    if not self.address and not self.fingerprint:
      raise ValueError("We need either a '%s.address' or '%s.fingerprint' to track" % (identifier, identifier))

  def __str__(self):
    attr = []

    if self.address:
      attr.append('address: %s' % self.address)

    if self.fingerprint:
      attr.append('fingerprint: %s' % self.fingerprint)

    return '%s (%s)' % (self.identifier, ', '.join(attr))


def get_tracked_relays():
  """
  Provides the relays we're tracking.

  :returns: **list** of **TrackedRelay** we're tracking

  :raises: **ValueError** if our config file is malformed
  """

  config = stem.util.conf.get_config('tracked_relays')
  config.load(util.get_path('data', 'tracked_relays.cfg'))

  # TODO: check for expired entries

  identifiers = set([key.split('.')[0] for key in config.keys()])
  return [TrackedRelay(identifier, config) for identifier in identifiers]


def main():
  # Map addresses and fingerprints to relays for constant time lookups. Address
  # ranges are handled separately cuz... well, they're a pita.

  tracked_addresses = {}
  tracked_address_ranges = {}
  tracked_fingerprints = {}

  for relay in get_tracked_relays():
    if relay.address:
      if '/' in relay.address:
        tracked_address_ranges[relay.address] = relay
      else:
        tracked_addresses[relay.address] = relay

    if relay.fingerprint:
      tracked_fingerprints[relay.fingerprint] = relay

  downloader = stem.descriptor.remote.DescriptorDownloader()
  found_relays = {}  # mapping of TrackedRelay => RouterStatusEntry

  for desc in downloader.get_consensus():
    if desc.address in tracked_addresses:
      found_relays[tracked_addresses[desc.address]] = desc
    elif desc.fingerprint in tracked_fingerprints:
      found_relays[tracked_fingerprints[desc.fingerprint]] = desc
    else:
      pass  # TODO: implement for tracked_address_ranges

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
