#!/usr/bin/env python
# Copyright 2017-2019, Damian Johnson and The Tor Project
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

MAC_VERSION = '\w*<td>([0-9\.]+)</td>'
DEBIAN_VERSION = '<h1>Source Package: \S+ \(([0-9\.]+).*\)'
FEDORA_VERSION = '<div class="package-name">([0-9\.]+).*</div>'
ARCH_LINUX_VERSION = '<title>Arch Linux - \S+ ([0-9\.]+).*</title>'
AUR_VERSION = '<h2>Package Details: \S+ ([0-9\.]+)-\S+</h2>'
FREEBSD_VERSION = 'SHA256 \(\S+-([0-9\.]+).tar.[gx]z\)'
OPENBSD_DIST_VERSION = 'DISTNAME\s*=\s+\S+-([0-9\.]+)'
OPENBSD_EGG_VERSION = 'MODPY_EGG_VERSION =\s+([0-9\.]+)'
NETBSD_VERSION = 'CURRENT, <b>Version: </b>([0-9\.]+),'

COLUMN = '| %-10s | %-10s | %-10s | %-50s |'
DIV = '+%s+%s+%s+%s+' % ('-' * 12, '-' * 12, '-' * 12, '-' * 52)
TRAC_URL = 'https://trac.torproject.org/projects/tor/wiki/doc/packages'

Package = collections.namedtuple('Package', ['platform', 'url', 'regex'])

PACKAGES = [
  ('tor', [
    Package('mac', 'https://formulae.brew.sh/formula/tor', MAC_VERSION),
    Package('debian', 'https://packages.debian.org/source/sid/tor', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/tor', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-vpn/tor', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/x86_64/tor/', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/network/tor/', 'tor-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/tor/', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/tor/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', OPENBSD_DIST_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/tor', NETBSD_VERSION),
  ]),
  ('nyx', [
    Package('mac', 'https://formulae.brew.sh/formula/nyx', MAC_VERSION),
    Package('debian', 'https://packages.debian.org/source/sid/nyx', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/nyx', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-misc/nyx', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/any/nyx/', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/nyx/', 'nyx-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/nyx/', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/nyx/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', OPENBSD_EGG_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/nyx', NETBSD_VERSION),
  ]),
  ('stem', [
    Package('debian', 'https://packages.debian.org/source/sid/python-stem', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/python-stem', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-libs/stem', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/any/python-stem/', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/stem/', 'stem-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/py-stem/', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/py-stem/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', OPENBSD_EGG_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/py-stem', NETBSD_VERSION),
  ]),
  ('txtorcon', [
    Package('debian', 'https://packages.debian.org/source/sid/txtorcon', DEBIAN_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/dev-python/txtorcon', None),
    Package('archlinux', 'https://aur.archlinux.org/packages/python-txtorcon/', AUR_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/python/txtorcon/', 'txtorcon-([0-9\.]+).tar.gz'),
    Package('freebsd', 'https://www.freshports.org/security/py-txtorcon/', FREEBSD_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/py-txtorcon', NETBSD_VERSION),
  ]),
  ('torsocks', [
    Package('mac', 'https://formulae.brew.sh/formula/torsocks', MAC_VERSION),
    Package('debian', 'https://packages.debian.org/source/sid/torsocks', DEBIAN_VERSION),
    Package('fedora', 'https://apps.fedoraproject.org/packages/torsocks', FEDORA_VERSION),
    Package('gentoo', 'https://packages.gentoo.org/packages/net-proxy/torsocks', None),
    Package('archlinux', 'https://www.archlinux.org/packages/community/x86_64/torsocks/', ARCH_LINUX_VERSION),
    Package('slackware', 'https://slackbuilds.org/repository/14.2/network/torsocks/', 'torsocks \(([0-9\.]+)\)    </h2>'),
    Package('freebsd', 'https://www.freshports.org/net/torsocks/', FREEBSD_VERSION),
    Package('openbsd', 'https://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/net/torsocks/Makefile?rev=HEAD&content-type=text/x-cvsweb-markup', OPENBSD_DIST_VERSION),
    Package('netbsd', 'http://pkgsrc.se/net/torsocks', NETBSD_VERSION),
  ]),
  ('ooni probe', [
    Package('mac', 'https://formulae.brew.sh/formula/ooniprobe', MAC_VERSION),
    Package('archlinux', 'https://aur.archlinux.org/packages/ooniprobe/', AUR_VERSION),
  ]),
]

log = util.get_logger('package_versions')


def fetch_url(url):
  for i in range(3):
    try:
      return urllib2.urlopen(url, timeout = 5).read()
    except Exception as exc:
      if i < 2:
        time.sleep(2 ** i)
      else:
        raise IOError(str(exc))


def wiki_package_versions():
  # Provides versions present on the wiki of the form...
  #
  #   {project => {platform => version}}
  #
  # Unfortunately the wiki table lacks good handles to match against so this is
  # gonna be very, very brittle. That's fine though - this is just an effort
  # saving measure for me anyway. ;P

  request = fetch_url(TRAC_URL)
  version_entries = []
  expected_count = sum([len(packages) for project, packages in PACKAGES])

  for line in request.splitlines():
    m = re.search('<b>Version:</b> <a href=".*">(.*)</a>', line)

    if m:
      version_entries.append(m.group(1))

  if len(version_entries) != expected_count:
    raise IOError('Table on %s no longer matches what this daemon expects (had %i entries)' % (TRAC_URL, len(version_entries)))

  result, index = {}, 0

  for project, packages in PACKAGES:
    for pkg in packages:
      result.setdefault(project, {})[pkg.platform] = version_entries[index]
      index += 1

  return result


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

  try:
    wiki_versions = wiki_package_versions()
  except IOError as exc:
    return str(exc), True

  has_issue = False

  for project, packages in PACKAGES:
    lines.append(DIV)

    for package in packages:
      try:
        wiki_version = wiki_versions[project][package.platform]
      except KeyError:
        return 'Failed to get wiki version for %s on %s' % (project, package.platform), True

      try:
        request = fetch_url(package.url)

        if package.platform == 'gentoo':
          current_version = gentoo_version(request)
        else:
          match = re.search(package.regex, request)
          current_version = match.group(1) if match else None

        if not current_version:
          msg = 'unable to determine current version'
          has_issue = True
        elif current_version == wiki_version:
          msg = 'up to date'
        else:
          msg = 'current version is %s but wiki has %s' % (current_version, wiki_version)
          has_issue = True
      except IOError as exc:
        msg = 'unable to retrieve current version: %s' % exc

        # Gentoo's site fails pretty routinely. No need to generate notices for
        # it.

        if package.platform != 'gentoo':
          has_issue = True

      lines.append(COLUMN % (project, package.platform, wiki_version, msg))

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
