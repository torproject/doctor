#!/usr/bin/env python
# Copyright 2017, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Checks for outdated versions on the packages wiki...

  https://trac.torproject.org/projects/tor/wiki/doc/packages
"""

import collections
import re
import time
import urllib2

import util

DEBIAN_VERSION = '<h1>Package: \S+ \(([0-9\.]+).*\)'
FEDORA_VERSION = '<div class="package-name">([0-9\.]+).*</div>'
ARCH_LINUX_VERSION = '<title>Arch Linux - \S+ ([0-9\.]+).*</title>'
AUR_VERSION = '<h2>Package Details: \S+ ([0-9\.]+)-\S+</h2>'
FREEBSD_VERSION = 'SHA256 \(\S+-([0-9\.]+).tar.gz\)'
OPENBSD_DIST_VERSION = 'DISTNAME\s*=\s+\S+-([0-9\.]+)'
OPENBSD_EGG_VERSION = 'MODPY_EGG_VERSION =\s+([0-9\.]+)'
NETBSD_VERSION = 'CURRENT, <b>Version: </b>([0-9\.]+),'

COLUMN = '| %-10s | %-10s | %-10s | %-50s |'
DIV = '+%s+%s+%s+%s+' % ('-' * 12, '-' * 12, '-' * 12, '-' * 52)

Package = collections.namedtuple('Package', ['platform', 'url', 'version', 'regex'])

PACKAGES = [
  ('tor', [
    Package('mac', 'https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/tor.rb', '0.3.1.9', 'tor-([0-9\.]+).tar.gz'),
    Package('debian', 'https://packages.debian.org/sid/tor', '0.3.1.9', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/tor', '0.3.1.9', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-vpn/tor', '0.3.1.9', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/x86_64/tor/', '0.3.1.9', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/network/tor/', '0.3.1.9', 'tor-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/tor/', '0.3.1.9', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/tor/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', '0.3.1.9', OPENBSD_DIST_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/tor', '0.3.1.9', NETBSD_VERSION),
  ]),
  ('nyx', [
    Package('gentoo', 'https://packages.gentoo.org/packages/net-misc/nyx', '2.0.4', None),
    Package('archlinux', 'https://aur.archlinux.org/packages/nyx/', '2.0.4', AUR_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/nyx/', '2.0.4', 'nyx-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/nyx/', '2.0.4', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/nyx/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', '2.0.4', OPENBSD_EGG_VERSION),
  ]),
  ('stem', [
    Package('debian', 'https://packages.debian.org/sid/python-stem', '1.6.0', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/python-stem', '1.6.0', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-libs/stem', '1.6.0', None),
    Package('archlinux', 'https://aur.archlinux.org/packages/stem/', '1.6.0', AUR_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/stem/', '1.6.0', 'stem-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/py-stem/', '1.6.0', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/py-stem/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', '1.6.0', OPENBSD_EGG_VERSION),
  ]),
  ('txtorcon', [
    Package('debian', 'https://packages.debian.org/sid/python-txtorcon', '0.19.3', DEBIAN_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/dev-python/txtorcon', '0.19.3', None),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/txtorcon/', '0.19.3', 'txtorcon-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/py-txtorcon/', '0.19.3', FREEBSD_VERSION),
  ]),
  ('torsocks', [
    Package('mac', 'https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/torsocks.rb', '2.2.0', ':tag => "v([0-9\.]+)",'),
    Package('debian', 'https://packages.debian.org/sid/torsocks', '2.2.0', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/torsocks', '2.1.0', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-proxy/torsocks', '2.2.0', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/x86_64/torsocks/', '2.2.0', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/network/torsocks/', '2.2.0', 'torsocks \(([0-9\.]+)\)    </h2>'),
    Package('freebsd', 'https://www.freshports.org/net/torsocks/', '2.2.0', 'SHA256 \(dgoulet-torsocks-v([0-9\.]+)_GH0.tar.gz\)'),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/torsocks/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', '1.2', OPENBSD_DIST_VERSION),
  ]),
  ('ooni probe', [
    Package('mac', 'https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/ooniprobe.rb', '2.2.0', 'ooniprobe-([0-9\.]+).tar.gz'),
    Package('debian', 'https://packages.debian.org/sid/ooniprobe', '2.2.0', DEBIAN_VERSION),
    Package('archlinux', 'https://aur.archlinux.org/packages/ooniprobe/', '1.2.2', AUR_VERSION),
  ]),
]

log = util.get_logger('package_versions')


def gentoo_version(request):
  # Unlike other platforms gentoo lists all package versions, so we
  # need to figure out what's the latest.

  highest_version, highest_version_int = None, 0

  for version in set(re.findall('.ebuild">([0-9\.]+)(?:-r[0-9]+)?</a>', request)):
    version_int = 0

    for section in version.split('.'):
      version_int = (version_int * 10) + int(section)

    if version_int > highest_version_int:
      highest_version = version
      highest_version_int = version_int

  return highest_version


def email_content():
  lines = []
  lines.append(DIV)
  lines.append(COLUMN % ('Project', 'Platform', 'Version', 'Status'))

  has_issue = False

  for project, packages in PACKAGES:
    lines.append(DIV)

    for package in packages:
      request, request_exc = None, None

      for i in range(3):
        try:
          request = urllib2.urlopen(package.url, timeout = 5).read()
          break
        except Exception as exc:
          request_exc = exc  # note exception and retry

          if i != 2:
            time.sleep(2 ** i)

      if request:
        if package.platform == 'gentoo':
          current_version = gentoo_version(request)
        else:
          match = re.search(package.regex, request)
          current_version = match.group(1) if match else None

        if not current_version:
          msg = 'unable to determine current version'
          has_issue = True
        elif current_version == package.version:
          msg = 'up to date'
        else:
          msg = 'current version is %s but wiki has %s' % (current_version, package.version)
          has_issue = True
      else:
        msg = 'unable to retrieve current version: %s' % request_exc
        has_issue = True

      lines.append(COLUMN % (project, package.platform, package.version, msg))

  lines.append(DIV)
  return '\n'.join(lines), has_issue


if __name__ == '__main__':
  content, has_issue = email_content()

  if has_issue:
    try:
      util.send('Packages wiki possibly outdated', body = content, to = [util.ERROR_ADDRESS])
    except Exception as exc:
      log.warn("Unable to send email: %s" % exc)

  log.debug('\n' + content)
