#!/usr/bin/env python
# Copyright 2013, Damian Johnson and The Tor Project
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

EMAIL_SUBJECT = 'Unable to retrieve tor descriptors'

EMAIL_BODY = """\
Unable to retrieve the present %s...

source: %s
time: %s
error: %s
"""

log = util.get_logger('descriptor_checker')
util.log_stem_debugging('descriptor_checker')


def main():
  # retrieve the server and extrainfo descriptors from any authority

  targets = [
    ('server descriptors', '/tor/server/all'),
    ('extrainfo descriptors', '/tor/extra/all'),
  ]

  for descriptor_type, resource in targets:
    log.debug("Downloading %s..." % descriptor_type)

    query = stem.descriptor.remote.Query(
      resource,
      block = True,
      timeout = 60,
    )

    if not query.error:
      count = len(list(query))
      log.debug("  %i descriptors retrieved from %s in %0.2fs" % (count, query.download_url, query.runtime))
    else:
      log.warn("Unable to retrieve the %s: %s" % (descriptor_type, query.error))
      send_email(EMAIL_SUBJECT, descriptor_type, query)

  # download the consensus from each authority

  for authority in stem.descriptor.remote.get_authorities().values():
    # skip authorities that don't vote in the consensus
    if authority.v3ident is None:
      continue

    log.debug("Downloading the consensus from %s..." % authority.nickname)

    query = stem.descriptor.remote.Query(
      '/tor/status-vote/current/consensus',
      block = True,
      timeout = 60,
      endpoints = [(authority.address, authority.dir_port)],
      document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
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
    util.send(subject, body_text = EMAIL_BODY % (descriptor_type, query.download_url, timestamp, query.error), destination = util.ERROR_ADDRESS)
  except Exception, exc:
    log.warn("Unable to send email: %s" % exc)


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "descriptor_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body_text = msg, destination = util.ERROR_ADDRESS)
