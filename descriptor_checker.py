#!/usr/bin/env python

"""
Downloads the present server descriptors, extrainfo descriptors, and consensus
checking for any malformed entries. This is meant to be ran hourly to ensure
that the directory authorities don't publish anything that's invalid. This
issues an email notification when a problem is discovered.
"""

import datetime
import logging
import os
import smtplib
import time

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import stem.descriptor
import stem.descriptor.remote

SENDER_ACCOUNT = 'verelsa@gmail.com'
SENDER_PASSWORD = ''
DESTINATION = 'atagar@torproject.org'
SUBJECT = 'Unable to retrieve tor descriptors'
BODY = """\
Unable to retrieve the present %s...

source: %s
time: %s
error: %s
"""

script_dir = os.path.dirname(os.path.abspath(__file__))

handler = logging.FileHandler(os.path.join(script_dir, 'descriptor_checker.log'))
handler.setFormatter(logging.Formatter(
  fmt = '%(asctime)s [%(levelname)s] %(message)s',
  datefmt = '%m/%d/%Y %H:%M:%S',
))

log = logging.getLogger("descriptor_checker")
log.setLevel(logging.DEBUG)
log.addHandler(handler)


def main():
  # retrieve the server and extrainfo descriptors from any authority

  targets = [
    ('server descriptors', '/tor/server/all.z'),
    ('extrainfo descriptors', '/tor/extra/all.z'),
  ]

  for descriptor_type, resource in targets:
    start_time = time.time()
    log.debug("Downloading %s..." % descriptor_type)

    query = stem.descriptor.remote.Query(
      resource,
      timeout = 60,
    )

    query.run(True)

    if not query.error:
      count = len(list(query))
      runtime = time.time() - start_time
      log.debug("  %i descriptors retrieved from %s in %0.2fs" % (count, query.download_url, runtime))
    else:
      log.warn("Unable to retrieve the %s: %s" % (descriptor_type, query.error))
      send_email(descriptor_type, query)

  # download the consensus from each authority

  for authority, endpoint in stem.descriptor.remote.DIRECTORY_AUTHORITIES.items():
    start_time = time.time()
    log.debug("Downloading the consensus from %s..." % authority)

    query = stem.descriptor.remote.Query(
      '/tor/status-vote/current/consensus.z',
      timeout = 60,
      endpoints = [endpoint],
      fall_back_to_authority = False,
      document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
    )

    query.run(True)

    if not query.error:
      count = len(list(query)[0].routers)
      runtime = time.time() - start_time
      log.debug("  %i descriptors retrieved from %s in %0.2fs" % (count, query.download_url, runtime))
    else:
      log.warn("Unable to retrieve the consensus from %s: %s" % (authority, query.error))
      send_email('consensus', query)


def send_email(descriptor_type, query):
  """
  Sends an email via gmail, returning if successful or not.
  """

  timestamp = datetime.datetime.now().strftime("%m/%d/%Y %H:%M")
  body = BODY % (descriptor_type, query.download_url, timestamp, query.error)

  msg = MIMEMultipart('alternative')
  msg['Subject'] = SUBJECT
  msg['From'] = SENDER_ACCOUNT
  msg['To'] = DESTINATION

  msg.attach(MIMEText(body, 'plain'))

  try:
    # send the message via the gmail SMTP server
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.starttls()
    server.login(SENDER_ACCOUNT, SENDER_PASSWORD)

    server.sendmail(SENDER_ACCOUNT, [DESTINATION], msg.as_string())
    server.quit()
  except smtplib.SMTPAuthenticationError, exc:
    log.warn("Unable to send email, authentication failure: %s" % exc)


if __name__ == '__main__':
  main()
