#!/usr/bin/env python
# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Health checks for your relay. This provides a simple email notification when
your relay becomes unavailable.
"""

import smtplib
import traceback

import stem
import stem.descriptor.remote

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

RELAY_ADDRESS = '208.113.135.162'
RELAY_OR_PORT = 1443
RELAY_NAME = 'caersidi'
RELAY_FINGERPRINT = '3BB34C63072D9D10E836EE42968713F7B9325F66'

EMAIL_ADDRESS = 'atagar@torproject.org'
RELAY_LINK = 'https://metrics.torproject.org/rs.html#details/%s' % RELAY_FINGERPRINT


def main():
  try:
    desc = stem.descriptor.remote.their_server_descriptor(
      endpoints = [stem.ORPort(RELAY_ADDRESS, RELAY_OR_PORT)],
    ).run()[0]

    if desc.nickname != RELAY_NAME:
      raise ValueError('Unexpected descriptor:\n\n%s' % desc)
  except stem.SocketError:
    email('Unable to reach %s' % RELAY_NAME, "Unable to reach %s (%s):\n\n%s" % (RELAY_NAME, RELAY_LINK, traceback.format_exc()))


def email(subject, body):
  """
  Sends an email notification via the local mail application.

  :param str subject: email subject
  :param str body: email content

  :raises: **Exception** if the email fails to be sent
  """

  msg = MIMEMultipart('alternative')
  msg['Subject'] = subject
  msg['To'] = EMAIL_ADDRESS

  msg.attach(MIMEText(body, 'plain'))

  server = smtplib.SMTP('localhost')
  server.sendmail('no-rely@torproject.com', [EMAIL_ADDRESS], msg.as_string())
  server.quit()


if __name__ == '__main__':
  try:
    main()
  except:
    email('Health check error', "Unable to check the health of %s (%s):\n\n%s" % (RELAY_NAME, RELAY_LINK, traceback.format_exc()))
