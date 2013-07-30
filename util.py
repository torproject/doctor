"""
Module for issuing email notifications to me via gmail.
"""

import logging
import os
import smtplib

from email import Encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.MIMEBase import MIMEBase

FROM_ADDRESS = 'verelsa@gmail.com'
TO_ADDRESS = 'atagar@torproject.org'
PASSWORD = None


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


def send(subject, body_text = None, body_html = None, attachment = None):
  """
  Sends an email notification via gmail.

  :param str subject: subject of the email
  :param str body_text: plaintext body of the email
  :param str body_html: html body of the email
  :param str attachment: path of a file to attach

  :raises: **Exception** if the email fails to be sent
  """

  msg = MIMEMultipart('alternative')
  msg['Subject'] = subject
  msg['From'] = FROM_ADDRESS
  msg['To'] = TO_ADDRESS

  if body_text:
    msg.attach(MIMEText(body_text, 'plain'))

  if body_html:
    msg.attach(MIMEText(body_html, 'html'))

  if attachment:
    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(attachment, "rb").read())
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attachment))
    msg.attach(part)

  # send the message via the gmail SMTP server
  server = smtplib.SMTP('smtp.gmail.com:587')
  server.starttls()
  server.login(FROM_ADDRESS, _get_password())
  server.sendmail(FROM_ADDRESS, [TO_ADDRESS], msg.as_string())
  server.quit()


def _get_password():
  """
  Provides the password for our gmail account. This is expected to be in a
  local 'gmail_pw' file.

  :returns: **str** with our gmail password

  :raises: **ValueError** if our password file is unavalable or can't be read
  """

  global PASSWORD

  if PASSWORD is None:
    pw_path = os.path.abspath('gmail_pw')

    if not os.path.exists(pw_path):
      raise ValueError("Unable to determine our gmail password, '%s' doesn't exist" % pw_path)

    try:
      PASSWORD = open(pw_path).read().strip()
    except Exception, exc:
      raise ValueError('Unable to determine our gmail password: %s' % exc)

  return PASSWORD
