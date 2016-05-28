"""
Module for issuing email notifications to me via gmail.
"""

import logging
import os
import socket
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import stem.util.connection
import stem.util.log

FROM_ADDRESS = 'atagar@torproject.org'
TO_ADDRESSES = ['tor-consensus-health@lists.torproject.org']
ERROR_ADDRESS = 'atagar@torproject.org'

TEST_RUN = False  # print script results rather than emailing


def get_path(*comp):
  """
  Provides a path relative of these scripts.

  :returns: absolute path, relative of these scripts
  """

  return os.path.abspath(os.path.join(os.path.dirname(__file__), *comp))


def get_logger(name):
  """
  Provides a logger configured to write to our local 'logs' directory.

  :param str name: name of our log file

  :returns: preconfigured logger
  """

  log_dir = get_path('logs')

  if not os.path.exists(log_dir):
    os.mkdir(log_dir)

  handler = logging.FileHandler(os.path.join(log_dir, name))
  handler.setFormatter(logging.Formatter(
    fmt = '%(asctime)s [%(levelname)s] %(message)s',
    datefmt = '%m/%d/%Y %H:%M:%S',
  ))

  log = logging.getLogger(name)
  log.setLevel(logging.DEBUG)
  log.addHandler(handler)

  return log


def is_reachable(address, port):
  return check_reachability(address, port) == None


def check_reachability(address, port):
  """
  Simple check to see if we can establish a connection to the given endpoint.

  :param str address: IPv4 or IPv6 address to check
  :param int port: port to check

  :returns: **None** if the endpoint is reachable and a **str** describing the issue otherwise
  """

  socket_type = socket.AF_INET6 if stem.util.connection.is_valid_ipv6_address(address) else socket.AF_INET
  test_socket = socket.socket(socket_type, socket.SOCK_STREAM)

  try:
    test_socket.connect((address, port))
    return None
  except Exception as exc:
    return str(exc)
  finally:
    test_socket.close()


def log_stem_debugging(name):
  """
  Logs trace level stem output to the given log file.

  :param str name: prefix name for our log file
  """

  log_dir = get_path('logs')

  if not os.path.exists(log_dir):
    os.mkdir(log_dir)

  handler = logging.FileHandler(os.path.join(log_dir, name + '.stem_debug'))
  handler.setFormatter(logging.Formatter(
    fmt = '%(asctime)s [%(levelname)s] %(message)s',
    datefmt = '%m/%d/%Y %H:%M:%S',
  ))

  log = stem.util.log.get_logger()
  log.addHandler(handler)


def send(subject, body, to = TO_ADDRESSES, cc = None, bcc = None):
  """
  Sends an email notification via the local mail application.

  :param str subject: subject of the email
  :param str body_text: plaintext body of the email
  :param list to: destinations for the to field
  :param list cc: destinations for the cc field
  :param list bcc: destinations for the bcc field

  :raises: **Exception** if the email fails to be sent
  """

  if TEST_RUN:
    print('Email to: %s' % to)
    print('Subject: %s' % subject)
    print('-' * 60)
    print(body)
    return

  msg = MIMEMultipart('alternative')
  msg['Subject'] = subject
  msg['From'] = FROM_ADDRESS
  msg['To'] = ','.join(to)

  destinations = to

  if cc:
    msg['Cc'] = ','.join(cc)
    destinations += cc

  if bcc:
    destinations += bcc

  msg.attach(MIMEText(body, 'plain'))

  server = smtplib.SMTP('localhost')
  server.sendmail(FROM_ADDRESS, destinations, msg.as_string())
  server.quit()
