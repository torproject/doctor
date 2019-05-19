#!/usr/bin/env python
# Copyright 2016-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Report for how many of our fallback directories are unreachable.
"""

import time
import traceback

import stem.descriptor.remote
import stem.directory

import util

log = util.get_logger('fallback_directories')

NOTIFICATION_THRESHOLD = 25  # send notice if this percentage of fallbacks are unusable
TO_ADDRESSES = ['tor-consensus-health@lists.torproject.org', 'teor@torproject.org', 'nickm@torproject.org', 'gus@torproject.org']
EMAIL_SUBJECT = 'Fallback Directory Summary (%i/%i, %i%%)'

EMAIL_BODY = """\
%i/%i (%i%%) fallback directories have become slow or unresponsive...

"""

downloader = stem.descriptor.remote.DescriptorDownloader(timeout = 30)


def main():
  try:
    fallback_directories = stem.directory.Fallback.from_remote().values()
    log.info('Retrieved %i fallback directories' % len(fallback_directories))
  except IOError as exc:
    raise IOError("Unable to determine tor's fallback directories: %s" % exc)

  issues = []

  for relay in fallback_directories:
    if not util.is_reachable(relay.address, relay.or_port):
      log.info('%s ORPort unreachable' % relay.fingerprint)
      issues.append('%s => ORPort is unreachable (%s:%i)' % (relay.fingerprint, relay.address, relay.or_port))
      continue

    if not util.is_reachable(relay.address, relay.dir_port):
      log.info('%s DirPort unreachable' % relay.fingerprint)
      issues.append('%s => DirPort is unreachable (%s:%i)' % (relay.fingerprint, relay.address, relay.dir_port))
      continue

    if relay.orport_v6 and not util.is_reachable(relay.orport_v6[0], relay.orport_v6[1]):
      log.info('%s IPv6 ORPort unreachable' % relay.fingerprint)
      issues.append('%s => IPv6 ORPort is unreachable (%s:%i)' % (relay.fingerprint, relay.orport_v6[0], relay.orport_v6[1]))
      continue

    try:
      start = time.time()
      downloader.get_consensus(endpoints = [(relay.address, relay.dir_port)]).run()
      download_time = time.time() - start
      log.info('%s download time was %0.1f seconds' % (relay.fingerprint, download_time))
    except Exception as exc:
      issues.append('%s => Unable to download from DirPort (%s)' % (relay.fingerprint, exc))
      continue

    if download_time > 15:
      issues.append('%s => Downloading the consensus took %0.1f seconds' % (relay.fingerprint, download_time))

  issue_percent = 100.0 * len(issues) / len(fallback_directories)
  log.info('%i issues found (%i%%)' % (len(issues), issue_percent))

  if issue_percent >= NOTIFICATION_THRESHOLD:
    log.info('Sending notification')

    subject = EMAIL_SUBJECT % (len(issues), len(fallback_directories), issue_percent)
    body = EMAIL_BODY % (len(issues), len(fallback_directories), issue_percent)
    util.send(subject, body = body + '\n'.join(['  * %s' % issue for issue in issues]), to = TO_ADDRESSES)

    # notification for #tor-bots

    body = '\n'.join(['[fallback-directories] %s' % issue for issue in issues])
    util.send('Announce or', body = body, to = ['tor-misc@commit.noreply.org'])


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "fallback_directories.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
