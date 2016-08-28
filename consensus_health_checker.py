#!/usr/bin/env python
# Copyright 2013-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import collections
import datetime
import os
import time
import traceback

import util

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem import Flag
from stem.util.lru_cache import lru_cache

Runlevel = stem.util.enum.UppercaseEnum('NOTICE', 'WARNING', 'ERROR')

DIRECTORY_AUTHORITIES = stem.descriptor.remote.get_authorities()
EMAIL_SUBJECT = 'Consensus issues'

CONFIG = stem.util.conf.config_dict('consensus_health', {
  'msg': {},
  'suppression': {},
  'known_params': [],
  'contact_address': {},
  'contact_via_bcc': [],
})

log = util.get_logger('consensus_health_checker')
util.log_stem_debugging('consensus_health_checker')

downloader = stem.descriptor.remote.DescriptorDownloader(
  timeout = 60,
  fall_back_to_authority = False,
  document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
)

Destination = collections.namedtuple('Destination', ('address', 'bcc'))


class Issue(object):
  """
  Problem to be reported at the end of the run.
  """

  def __init__(self, runlevel, template, **attr):
    self._runlevel = runlevel
    self._template = template
    self._attr = attr

    self._authorities = attr.get('to', [])

  @lru_cache()
  def get_message(self):
    """
    Provides the description of the problem.

    :returns: **str** with a description of the issue
    """

    if self._template in CONFIG['msg']:
      try:
        return CONFIG['msg'][self._template].format(**self._attr)
      except:
        log.error("Unable to apply formatted string attributes to msg.%s: %s" % (self._template, self._attr))
    else:
      log.error("Missing configuration value: msg.%s" % self._template)

    return ''

  def get_runlevel(self):
    """
    Provides the runlevel of this issue.

    :reutrns: **Runlevel** for the runlevel of the issue
    """

    return self._runlevel

  @lru_cache()
  def get_destinations(self):
    """
    Provides a mapping of authorities with this issue to their Destination. The
    destination is **None** if no contact information has been configured.

    :returns: **dict** of authorities this concerns to their contact information
    """

    destinations = {}

    for authority in self._authorities:
      if authority in CONFIG['contact_address']:
        address = CONFIG['contact_address'][authority]
        is_via_bcc = authority in CONFIG['contact_via_bcc']

        destinations[authority] = Destination(address, is_via_bcc)
      else:
        destinations[authority] = None

    return destinations

  @lru_cache()
  def get_suppression_key(self):
    """
    Provides the key used for issue suppression.

    :returns: **str** used for the configuration key of this issue in the
      suppressions file
    """

    if self._template == 'TOO_MANY_UNMEASURED_RELAYS':
      # Hack because this message has too much dynamic data to be effectively
      # suppressed. Hate doing this here, so better would be to make this a
      # config property.

      attr = dict(self._attr)
      attr.update({'unmeasured': 0, 'total': 0, 'percentage': 0})

      return CONFIG['msg'][self._template].format(**attr).replace(' ', '_')
    elif self._template == 'BANDWIDTH_AUTHORITIES_OUT_OF_SYNC':
      attr = dict(self._attr)
      attr.update({'authorities': ''})

      return CONFIG['msg'][self._template].format(**attr).replace(' ', '_')
    elif self._template == 'LATENCY':
      attr = dict(self._attr)
      attr.update({'authority': '', 'time_taken': '', 'median_time': '', 'authority_times': ''})

      return CONFIG['msg'][self._template].format(**attr).replace(' ', '_')
    else:
      return self.get_message().replace(' ', '_')

  @lru_cache()
  def get_suppression_duration(self):
    """
    Provides the number of hours we should suppress this message after it has
    been shown. This is zero if the message shouldn't be suppressed.

    :returns: **int** for the number of hours the message should be suppressed
      after its been shown
    """

    if self._template in CONFIG['suppression']:
      suppression_duration = CONFIG['suppression'][self._template]

      try:
        return int(suppression_duration)
      except ValueError:
        log.error("Non-numic suppression time (%s): %s" % (self._template, suppression_duration))

    # Default to suppression based on the severity of the issue.

    if self.get_runlevel() == Runlevel.NOTICE:
      return 24  # 1 day
    elif self.get_runlevel() == Runlevel.WARNING:
      return 4  # 4 hours
    else:
      return 0  # no suppression for errors

  def __str__(self):
    return "%s: %s" % (self.get_runlevel(), self.get_message())


def is_rate_limited(issue):
  """
  Check if we have sent a notice with this key within a given period of time.

  :param Issue issue: issue to check the suppression status for
  """

  key = issue.get_suppression_key()
  hours = issue.get_suppression_duration()

  if hours == 0:
    return True

  current_time = int(time.time())
  last_seen = stem.util.conf.get_config('last_notified').get(key, 0)
  suppression_time = 3600 * hours
  suppression_time += 1800  # adding a half hour so timing doesn't coinside with our hourly cron
  suppression_time_remaining = suppression_time - (current_time - last_seen)

  if suppression_time_remaining <= 0:
    return False
  else:
    log.info("Suppressing %s, time remaining is %i hours" % (key, (suppression_time_remaining / 3600) + 1))
    return True


def rate_limit_notice(issue):
  """
  Record that this notice is being sent, so further runs will take this into
  account for rate limitation.

  :param Issue issue: issue to update the suppression status for
  """

  key = issue.get_suppression_key()
  hours = issue.get_suppression_duration()

  if hours == 0:
    return

  config = stem.util.conf.get_config('last_notified')
  config.set(key, str(int(time.time())), overwrite = True)
  config.save()


def main():
  start_time = time.time()

  # loads configuration data

  config = stem.util.conf.get_config("consensus_health")
  config.load(util.get_path('data', 'consensus_health.cfg'))

  contact_path = util.get_path('data', 'contact_information.cfg')

  if os.path.exists(contact_path):
    config.load(contact_path)

  config = stem.util.conf.get_config('last_notified')
  last_notified_path = util.get_path('data', 'last_notified.cfg')

  if os.path.exists(last_notified_path):
    config.load(last_notified_path)
  else:
    config._path = last_notified_path

  consensuses, consensus_fetching_issues = get_consensuses()
  votes, vote_fetching_issues = get_votes()
  issues = consensus_fetching_issues + vote_fetching_issues

  if consensuses and votes:
    issues += run_checks(consensuses, votes)
  else:
    log.warn("Unable to retrieve any votes. Skipping checks.")

  is_all_suppressed = True  # either no issues or they're all already suppressed

  for issue in issues:
    if not is_rate_limited(issue):
      is_all_suppressed = False
      break

  if not is_all_suppressed:
    destinations = {}

    for issue in issues:
      rate_limit_notice(issue)
      destinations.update(issue.get_destinations())

    destination_labels = []

    for authority, destination in destinations.items():
      if not destination:
        destination_labels.append('%s has no contact information' % authority)
      elif not destination.bcc:
        destination_labels.append('%s at %s' % (authority, destination.address))
      else:
        destination_labels.append('%s at %s via bcc' % (authority, destination.address))

    log.debug('Sending notification for issues (%s)' % ', '.join(destination_labels))

    body = '\n'.join(map(str, issues))
    cc = [d.address for d in destinations.values() if d and not d.bcc]
    bcc = [d.address for d in destinations.values() if d and d.bcc]

    util.send(EMAIL_SUBJECT, body = body, cc = cc, bcc = bcc)

    # notification for #tor-bots

    body = '\n'.join(['[consensus-health] %s' % issue for issue in issues])
    util.send('Announce or', body = body, to = ['tor-misc@commit.noreply.org'])
  else:
    if issues:
      log.info("All %i issues were suppressed. Not sending a notification." % len(issues))
    else:
      log.info("No issues found.")

  log.debug("Checks finished, runtime was %0.2f seconds" % (time.time() - start_time))


def run_checks(consensuses, votes):
  """
  Performs our checks against the given consensus and vote documents. Checker
  functions are expected to be of the form...

    my_check(latest_consensus, consensuses, votes) => Issue or list of Issues

  :param dict consensuses: mapping of authorities to their consensus
  :param dict votes: mapping of authorities to their votes
  """

  latest_consensus, latest_valid_after = None, None

  for consensus in consensuses.values():
    if not latest_valid_after or consensus.valid_after > latest_valid_after:
      latest_consensus = consensus
      latest_valid_after = consensus.valid_after

  checker_functions = (
    missing_latest_consensus,
    consensus_method_unsupported,
    different_recommended_client_version,
    different_recommended_server_version,
    unknown_consensus_parameters,
    #vote_parameters_mismatch_consensus,
    certificate_expiration,
    consensuses_have_same_votes,
    #has_all_signatures,
    voting_bandwidth_scanners,
    #unmeasured_relays,
    has_authority_flag,
    is_recommended_versions,
    bad_exits_in_sync,
    bandwidth_authorities_in_sync,
    is_orport_reachable,
  )

  all_issues = []

  for checker in checker_functions:
    issues = checker(latest_consensus, consensuses, votes)

    if issues:
      if isinstance(issues, Issue):
        issues = [issues]

      for issue in issues:
        log.debug(issue)
        all_issues.append(issue)

  return all_issues


def missing_latest_consensus(latest_consensus, consensuses, votes):
  "Checks that none of the consensuses are more than an hour old."

  stale_authorities = []
  current_time = datetime.datetime.now()

  for authority, consensus in consensuses.items():
    if (current_time - consensus.valid_after) > datetime.timedelta(hours = 1):
      stale_authorities.append(authority)

  if stale_authorities:
    runlevel = Runlevel.ERROR if len(stale_authorities) > 3 else Runlevel.WARNING
    return Issue(runlevel, 'MISSING_LATEST_CONSENSUS', authorities = ', '.join(stale_authorities), to = stale_authorities)


def consensus_method_unsupported(latest_consensus, consensuses, votes):
  "Checks that all of the votes support the present consensus method."

  incompatible_authorities = []

  for authority, vote in votes.items():
    if not latest_consensus.consensus_method in vote.consensus_methods:
      incompatible_authorities.append(authority)

  if incompatible_authorities:
    return Issue(Runlevel.WARNING, 'CONSENSUS_METHOD_UNSUPPORTED', authorities = ', '.join(incompatible_authorities), to = incompatible_authorities)


def different_recommended_client_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for clients match the present consensus."

  differences = {}

  for authority, vote in votes.items():
    if vote.client_versions and latest_consensus.client_versions != vote.client_versions:
      differences[authority] = _version_difference_str(authority, latest_consensus.client_versions, vote.client_versions)

  if differences:
    return Issue(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', type = 'client', differences = ', '.join(differences.values()), to = differences.keys())


def different_recommended_server_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for servers match the present consensus."

  differences = {}

  for authority, vote in votes.items():
    if vote.server_versions and latest_consensus.server_versions != vote.server_versions:
      differences[authority] = _version_difference_str(authority, latest_consensus.server_versions, vote.server_versions)

  if differences:
    return Issue(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', type = 'server', differences = ', '.join(differences.values()), to = differences.keys())


def _version_difference_str(authority, consensus_versions, vote_versions):
  """
  Provide a description of the delta between the given consensus and vote
  versions. For instance...

    moria1 +1.0.0.1-dev -0.0.8.6 -0.0.8.9
  """

  consensus_versions = set(consensus_versions)
  vote_versions = set(vote_versions)

  msg = authority

  for extra_version in vote_versions.difference(consensus_versions):
    msg += ' +%s' % extra_version

  for missing_version in consensus_versions.difference(vote_versions):
    msg += ' -%s' % missing_version

  return msg


def unknown_consensus_parameters(latest_consensus, consensuses, votes):
  "Checks that votes don't contain any parameters that we don't recognize."

  unknown_entries = {}

  for authority, vote in votes.items():
    unknown_params = []

    for param_key, param_value in vote.params.items():
      if not param_key in CONFIG['known_params'] and not param_key.startswith('bwauth'):
        unknown_params.append('%s=%s' % (param_key, param_value))

    if unknown_params:
      unknown_entries[authority] = '%s %s' % (authority, ' '.join(unknown_params))

  if unknown_entries:
    return Issue(Runlevel.NOTICE, 'UNKNOWN_CONSENSUS_PARAMETERS', parameters = ', '.join(unknown_entries.values()), to = unknown_entries.keys())


def vote_parameters_mismatch_consensus(latest_consensus, consensuses, votes):
  "Check that all vote parameters appear in the consensus."

  mismatching_entries = {}

  for authority, vote in votes.items():
    mismatching_params = []

    for param_key, param_value in vote.params.items():
      if latest_consensus.params.get(param_key) != param_value:
        mismatching_params.append('%s=%s' % (param_key, param_value))

    if mismatching_params:
      mismatching_entries[authority] = '%s %s' % (authority, ' '.join(mismatching_params))

  if mismatching_entries:
    return Issue(Runlevel.NOTICE, 'MISMATCH_CONSENSUS_PARAMETERS', parameters = ', '.join(mismatching_entries.values()), to = mismatching_entries.keys())


def certificate_expiration(latest_consensus, consensuses, votes):
  "Check if an authority's certificate is about to expire."

  issues = []
  current_time = datetime.datetime.now()

  for authority, vote in votes.items():
    # votes should only have a single authority entry (the one that issued this vote)

    cert_expiration = vote.directory_authorities[0].key_certificate.expires
    expiration_label = '%s (%s)' % (authority, cert_expiration.strftime('%Y-%m-%d %H-%M-%S'))

    if (cert_expiration - current_time) <= datetime.timedelta(days = 7):
      issues.append(Issue(Runlevel.WARNING, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'week', authority = expiration_label, to = [authority]))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 14):
      issues.append(Issue(Runlevel.WARNING, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'two weeks', authority = expiration_label, to = [authority]))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 21):
      issues.append(Issue(Runlevel.NOTICE, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'three weeks', authority = expiration_label, to = [authority]))

  return issues


def consensuses_have_same_votes(latest_consensus, consensuses, votes):
  "Checks that all fresh consensuses are made up of the same votes."

  current_time = datetime.datetime.now()
  fresh_consensuses = dict((k, v) for k, v in consensuses.items() if ((current_time - v.valid_after) < datetime.timedelta(hours = 1)))

  all_votes = set()

  for consensus in fresh_consensuses.values():
    all_votes.update(set([auth.fingerprint for auth in consensus.directory_authorities]))

  authorities_missing_votes = []

  for authority, consensus in fresh_consensuses.items():
    if set([auth.fingerprint for auth in consensus.directory_authorities]) != all_votes:
      authorities_missing_votes.append(authority)

  if authorities_missing_votes:
    return Issue(Runlevel.NOTICE, 'MISSING_VOTES', authorities = ', '.join(authorities_missing_votes), to = authorities_missing_votes)


def has_all_signatures(latest_consensus, consensuses, votes):
  "Check that the consensuses have signatures for authorities that voted on it."

  issues = []
  voting_authorities = set([authority.v3ident for authority in DIRECTORY_AUTHORITIES.values() if authority.v3ident])

  for consensus_of, consensus in consensuses.items():
    signing_authorities = set([sig.identity for sig in consensus.signatures])
    missing_authorities = set()

    for missing_signature in voting_authorities.difference(signing_authorities):
      # Attempt to translate the missing v3ident signatures into authority
      # nicknames, falling back to just notifying of the v3ident if not found.

      missing_authority = missing_signature

      for authority in DIRECTORY_AUTHORITIES.values():
        if authority.v3ident == missing_signature:
          missing_authority = authority.nickname
          break

      missing_authorities.add(missing_authority)

    if missing_authorities:
      issues.append(Issue(Runlevel.NOTICE, 'MISSING_SIGNATURE', consensus_of = consensus_of, authorities = ', '.join(missing_authorities), to = missing_authorities))

  return issues


def voting_bandwidth_scanners(latest_consensus, consensuses, votes):
  "Checks that we have bandwidth scanner results from the authorities that vote on it."

  missing_authorities, extra_authorities = [], []

  for authority, vote in votes.items():
    contains_measured_bandwidth = False

    for desc in vote.routers.values():
      if desc.measured:
        contains_measured_bandwidth = True
        break

    if DIRECTORY_AUTHORITIES[authority].is_bandwidth_authority and not contains_measured_bandwidth:
      missing_authorities.append(authority)
    if not DIRECTORY_AUTHORITIES[authority].is_bandwidth_authority and contains_measured_bandwidth:
      extra_authorities.append(authority)

  issues = []

  if missing_authorities:
    runlevel = Runlevel.ERROR if len(missing_authorities) > 1 else Runlevel.WARNING
    issues.append(Issue(runlevel, 'MISSING_BANDWIDTH_SCANNERS', authorities = ', '.join(missing_authorities), to = missing_authorities))

  if extra_authorities:
    issues.append(Issue(Runlevel.NOTICE, 'EXTRA_BANDWIDTH_SCANNERS', authorities = ', '.join(extra_authorities), to = extra_authorities))

  return issues


def unmeasured_relays(latest_consensus, consensuses, votes):
  "Checks that the bandwidth authorities have all formed an opinion about at least 90% of the relays."

  issues = []
  consensus_fingerprints = set([desc.fingerprint for desc in latest_consensus.routers.values()])

  for authority, vote in votes.items():
    if DIRECTORY_AUTHORITIES[authority].is_bandwidth_authority:
      measured, unmeasured = 0, 0

      for desc in vote.routers.values():
        if desc.fingerprint in consensus_fingerprints:
          if desc.measured:
            measured += 1
          else:
            unmeasured += 1

      total = measured + unmeasured
      percentage = 100 * unmeasured / total

      if percentage >= 5:
        issues.append(Issue(Runlevel.NOTICE, 'TOO_MANY_UNMEASURED_RELAYS', authority = authority.nickname, unmeasured = unmeasured, total = total, percentage = percentage, to = [authority]))

  return issues


def has_authority_flag(latest_consensus, consensuses, votes):
  "Checks that the authorities have the 'authority' flag in the present consensus."

  seen_authorities = set()

  for desc in latest_consensus.routers.values():
    if Flag.AUTHORITY in desc.flags:
      seen_authorities.add(desc.nickname)

  known_authorities = set(DIRECTORY_AUTHORITIES.keys())
  missing_authorities = known_authorities.difference(seen_authorities)
  extra_authorities = seen_authorities.difference(known_authorities)

  issues = []

  if missing_authorities:
    issues.append(Issue(Runlevel.WARNING, 'MISSING_AUTHORITIES', authorities = ', '.join(missing_authorities), to = missing_authorities))

  # TODO: Re-enable when Tonga is gone.

  #if extra_authorities:
  #  issues.append(Issue(Runlevel.NOTICE, 'EXTRA_AUTHORITIES', authorities = ', '.join(extra_authorities), to = extra_authorities))

  return issues


def has_expected_fingerprints(latest_consensus, consensuses, votes):
  "Checks that the authorities have the fingerprints that we expect."

  issues = []

  for desc in latest_consensus.routers.values():
    if desc.nickname in DIRECTORY_AUTHORITIES and Flag.NAMED in desc.flags:
      expected_fingerprint = DIRECTORY_AUTHORITIES[desc.nickname].fingerprint

      if desc.fingerprint != expected_fingerprint:
        issues.append(Issue(Runlevel.ERROR, 'FINGERPRINT_MISMATCH', authority = desc.nickname, expected = desc.fingerprint, actual = expected_fingerprint, to = [desc.nickname]))

  return issues


def is_recommended_versions(latest_consensus, consensuses, votes):
  "Checks that the authorities are running a recommended version or higher."

  outdated_authorities = {}
  min_version = min(latest_consensus.server_versions)

  for authority in DIRECTORY_AUTHORITIES.values():
    desc = latest_consensus.routers.get(authority.fingerprint)

    if desc and desc.version and desc.version < min_version:
      outdated_authorities[authority.nickname] = desc.version

  if outdated_authorities:
    entries = ['%s (%s)' % (k, v) for k, v in outdated_authorities.items()]
    return Issue(Runlevel.WARNING, 'TOR_OUT_OF_DATE', authorities = ', '.join(entries), to = outdated_authorities.keys())


def bad_exits_in_sync(latest_consensus, consensuses, votes):
  "Checks that the authorities that vote on the BadExit flag are in agreement."

  bad_exits = {}  # mapping of authorities to the fingerprints with the BadExit flag

  for authority, vote in votes.items():
    flagged = [desc.fingerprint for desc in vote.routers.values() if Flag.BADEXIT in desc.flags]

    if flagged:
      bad_exits[authority] = set(flagged)

  if not bad_exits:
    return

  voting_authorities = set(bad_exits.keys())
  agreed_bad_exits = set.intersection(*bad_exits.values())
  disagreed_bad_exits = set.union(*bad_exits.values()).difference(agreed_bad_exits)

  issues = []

  for fingerprint in disagreed_bad_exits:
    with_flag = set([authority for authority, flagged in bad_exits.items() if fingerprint in flagged])
    without_flag = []
    not_in_vote = []

    for authority in voting_authorities.difference(with_flag):
      vote = votes[authority]

      if fingerprint in vote.routers:
        without_flag.append(authority)
      else:
        not_in_vote.append(authority)

    if not without_flag:
      continue  # skip notice if the only disagreement is due to not having a vote

    # If this relay's missing from a consensus then don't bother. It gets
    # negligable traffic and is likely part of normal network churn.

    if fingerprint not in latest_consensus.routers:
      log.debug("BadExit sync check is skipping %s because it's not in the latest consensus" % fingerprint)
      continue

    attr = ['with flag: %s' % ', '.join(with_flag)]

    if without_flag:
      attr.append('without flag: %s' % ', '.join(without_flag))

    if not_in_vote:
      attr.append('not in vote: %s' % ', '.join(not_in_vote))

    issues.append(Issue(Runlevel.NOTICE, 'BADEXIT_OUT_OF_SYNC', fingerprint = fingerprint, counts = ', '.join(attr), to = bad_exits.keys()))

  return issues


def bandwidth_authorities_in_sync(latest_consensus, consensuses, votes):
  """
  Checks that the bandwidth authorities are reporting roughly the same number
  of measurements. This is in alarm if any of the authorities deviate by more
  than 20% from the average.
  """

  measurement_counts = {}  # mapping of authorities to the number of fingerprints with a measurement

  for authority, vote in votes.items():
    measured = [desc.fingerprint for desc in vote.routers.values() if desc.measured is not None]

    if measured:
      measurement_counts[authority] = len(measured)

  if not measurement_counts:
    return

  average = sum(measurement_counts.values()) / len(measurement_counts)

  for authority, count in measurement_counts.items():
    if count > (1.2 * average) or count < (0.8 * average):
      entries = ['%s (%s)' % (authority, count) for authority, count in measurement_counts.items()]
      return Issue(Runlevel.NOTICE, 'BANDWIDTH_AUTHORITIES_OUT_OF_SYNC', authorities = ', '.join(entries), to = measurement_counts.keys())


def is_orport_reachable(latest_consensus, consensuses, votes):
  """
  Simple check to see if we can reach the authority's ORPort.
  """

  issues = []

  for authority in DIRECTORY_AUTHORITIES.values():
    desc = latest_consensus.routers.get(authority.fingerprint)

    if not desc:
      continue  # authority isn't in the consensus

    for address, port, is_ipv6 in desc.or_addresses:
      issue = util.check_reachability(address, port)

      if issue:
        issues.append(Issue(Runlevel.WARNING, 'UNABLE_TO_REACH_ORPORT', authority = authority.nickname, address = address, port = port, error = issue, to = [authority]))

  return issues


def get_consensuses():
  """
  Provides a mapping of directory authority nicknames to their present consensus.

  :returns: tuple of the form ({authority => consensus}, issues)
  """

  return _get_documents('consensus', '/tor/status-vote/current/consensus.z')


def get_votes():
  """
  Provides a mapping of directory authority nicknames to their present vote.

  :returns: tuple of the form ({authority => vote}, issues)
  """

  return _get_documents('vote', '/tor/status-vote/current/authority.z')


def _get_documents(label, resource):
  documents, times_taken, issues = {}, {}, []

  for authority in DIRECTORY_AUTHORITIES.values():
    if authority.v3ident is None:
      continue  # not a voting authority

    query = downloader.query(
      resource,
      endpoints = [(authority.address, authority.dir_port)],
      default_params = False,
      validate = True,
    )

    try:
      start_time = time.time()
      documents[authority.nickname] = query.run()[0]
      times_taken[authority.nickname] = time.time() - start_time
    except Exception as exc:
      issues.append(Issue(Runlevel.ERROR, 'AUTHORITY_UNAVAILABLE', fetch_type = label, authority = authority.nickname, url = query.download_url, error = exc, to = [authority.nickname]))

  if label == 'consensus':
    median_time = sorted(times_taken.values())[len(times_taken) / 2]
    authority_times = ', '.join(['%s => %0.1fs' % (authority, time_taken) for authority, time_taken in times_taken.items()])

    for nickname, time_taken in times_taken.items():
      if time_taken > median_time * 5:
        issues.append(Issue(Runlevel.NOTICE, 'LATENCY', authority = nickname, time_taken = '%0.1fs' % time_taken, median_time = '%0.1fs' % median_time, authority_times = authority_times, to = [nickname]))

  return documents, issues


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "consensus_health_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body = msg, to = [util.ERROR_ADDRESS])
