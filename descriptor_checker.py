#!/usr/bin/env python
# Copyright 2013-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Downloads the present server descriptors, extrainfo descriptors, and consensus
checking for any malformed entries. This is meant to be ran hourly to ensure
that the directory authorities don't publish anything that's invalid. This
issues an email notification when a problem is discovered.
"""

import datetime
import os
import traceback

import util

import stem.descriptor
import stem.descriptor.remote
import stem.directory

EMAIL_SUBJECT = 'Unable to retrieve tor descriptors'

EMAIL_BODY = """\
Unable to retrieve the present %s...

source: %s
time: %s
error: %s
"""

DIRAUTH_SKIP_CHECKS = (
  'tor26'   # tor26 DirPort does not service requests without a .z suffix
)

log = util.get_logger('descriptor_checker')
util.log_stem_debugging('descriptor_checker')


def main():
  # retrieve the server and extrainfo descriptors from any authority

  targets = [
    ('server descriptors', '/tor/server/all.z'),
    ('extrainfo descriptors', '/tor/extra/all.z'),
  ]

  for descriptor_type, resource in targets:
    log.debug("Downloading %s..." % descriptor_type)

    query = stem.descriptor.remote.Query(
      resource,
      block = True,
      timeout = 60,
      validate = True,
    )

    if not query.error:
      count = len(list(query))
      log.debug("  %i descriptors retrieved from %s in %0.2fs" % (count, query.download_url, query.runtime))
    elif "'dirreq-v3-ips' line had non-ascii content" in str(query.error) or "Entries in dirreq-v3-ips line should only be" in str(query.error):
      log.debug("Suppressing error due to malformed dirreq-v3-ips line: https://trac.torproject.org/projects/tor/ticket/16858")
    else:
      log.warn("Unable to retrieve the %s: %s" % (descriptor_type, query.error))
      send_email(EMAIL_SUBJECT, descriptor_type, query)

  # download the consensus from each authority

  for authority in stem.directory.Authority.from_cache().values():
    if authority.v3ident is None:
      continue  # authority doesn't vote in the consensus
    elif authority.nickname in DIRAUTH_SKIP_CHECKS:
      continue  # checking of authority impaired

    log.debug("Downloading the consensus from %s..." % authority.nickname)

    query = stem.descriptor.remote.Query(
      '/tor/status-vote/current/consensus.z',
      block = True,
      timeout = 60,
      endpoints = [(authority.address, authority.dir_port)],
      document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
      validate = True,
    )

    if not query.error:
      count = len(list(query)[0].routers)
      log.debug("  %i descriptors retrieved from %s in %0.2fs" % (count, query.download_url, query.runtime))
    else:
      log.warn("Unable to retrieve the consensus from %s: %s" % (authority.nickname, query.error))

      subject = EMAIL_SUBJECT + ' (%s)' % authority.nickname
      send_email(subject, 'consensus', query)


def send_email(subject, descriptor_type, query):
  try:
    timestamp = datetime.datetime.now().strftime("%m/%d/%Y %H:%M")
    util.send(subject, body = EMAIL_BODY % (descriptor_type, query.download_url, timestamp, query.error), to = [util.ERROR_ADDRESS])
  except Exception as exc:
    log.warn("Unable to send email: %s" % exc)


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "descriptor_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
