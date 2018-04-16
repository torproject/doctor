#!/usr/bin/env python
# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Health checks for your relay. This provides a simple email notification when
your relay has become unavailable.
"""

import smtplib
import traceback

import stem
import stem.client

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
    with stem.client.Relay.connect(RELAY_ADDRESS, RELAY_OR_PORT, [3]) as relay:
      circ = relay.create_circuit()
      circ.send('RELAY_BEGIN_DIR', stream_id = 1)
      our_descriptor = circ.send('RELAY_DATA', 'GET /tor/server/authority HTTP/1.0\r\n\r\n', stream_id = 1).data
      circ.close()

      if 'router %s %s %s' % (RELAY_NAME, RELAY_ADDRESS, RELAY_OR_PORT) not in our_descriptor:
        email('Unable to fetch %s descriptor' % RELAY_NAME, "Unable to retrieve the descriptor of %s (%s):\n\n%s" % (RELAY_NAME, RELAY_LINK, our_descriptor))
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
  server.sendmail(FROM_ADDRESS, destinations, msg.as_string())
  server.quit()


if __name__ == '__main__':
  try:
    main()
  except:
    email('Health check error', "Unable to check the health of %s (%s):\n\n%s" % (RELAY_NAME, RELAY_LINK, traceback.format_exc()))
