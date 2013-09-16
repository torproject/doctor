#!/usr/bin/env python
# Copyright 2013, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import datetime
import time
import traceback

import util

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem import Flag

Runlevel = stem.util.enum.UppercaseEnum("NOTICE", "WARNING", "ERROR")

DIRECTORY_AUTHORITIES = stem.descriptor.remote.get_authorities()
EMAIL_SUBJECT = 'Consensus issues'

CONFIG = stem.util.conf.config_dict("consensus_health", {
  'msg': {},
  'bandwidth_authorities': [],
  'known_params': [],
})

log = util.get_logger('consensus_health_checker')
util.log_stem_debugging('consensus_health_checker')

downloader = stem.descriptor.remote.DescriptorDownloader(
  timeout = 60,
  fall_back_to_authority = False,
  document_handler = stem.descriptor.DocumentHandler.DOCUMENT,
)


class Issue(object):
  """
  Problem to be reported at the end of the run.

  :var str runlevel: runlevel of the issue
  :var str msg: description of the problem
  """

  def __init__(self, runlevel, msg):
    self.runlevel = runlevel
    self.msg = msg

  @staticmethod
  def for_msg(runlevel, template, *attr):
    """
    Provides an Issue for the given message from our config with any formatted
    string arguments inserted.

    :var str runlevel: runlevel of the issue
    :param str template: base string to fetch from our config
    :param list attr: formatted string arguments
    """

    if template in CONFIG['msg']:
      try:
        return Issue(runlevel, CONFIG['msg'][template] % attr)
      except:
        log.error("Unable to apply formatted string attributes to msg.%s: %s" % (template, attr))
    else:
      log.error("Missing configuration value: msg.%s" % template)

    return Issue(runlevel, '')

  def __str__(self):
    return "%s: %s" % (self.runlevel, self.msg)


def rate_limit_notice(key, hours = 0, days = 0):
  """
  Check if we have sent a notice with this key within a given period of time.
  If we have then this returns **False**, otherwise this records the fact that
  we're sending the message now and returns **True**.

  :param str key: unique identifier for this notification
  :param int hours: number of hours to suppress this message for after being sent
  :param int days: number of days to suppress this message for after being sent
  """

  config = stem.util.conf.get_config("last_notified")
  config_path = util.get_path('data', 'last_notified.cfg')

  try:
    config.clear()
    config.load(config_path)
  except:
    pass

  current_time = int(time.time())
  last_seen = config.get(key, 0)
  suppression_time = (3600 * hours) + (86400 * days)
  suppression_time += 1800  # adding a half hour so timing doesn't coinside with our hourly cron
  suppression_time_remaining = suppression_time - (current_time - last_seen)

  if suppression_time_remaining <= 0:
    config.set(key, str(current_time), overwrite = True)
    config.save(config_path)
    return True
  else:
    log.info("Suppressing %s, time remaining is %i hours" % (key, (suppression_time_remaining / 3600) + 1))
    return False


def main():
  start_time = time.time()

  # loads configuration data

  config = stem.util.conf.get_config("consensus_health")
  config.load(util.get_path('data', 'consensus_health.cfg'))

  consensuses, consensus_fetching_issues = get_consensuses()
  votes, vote_fetching_issues = get_votes()
  issues = consensus_fetching_issues + vote_fetching_issues

  if consensuses and votes:
    issues += run_checks(consensuses, votes)
  else:
    log.warn("Unable to retrieve any votes. Skipping checks.")

  if issues:
    log.debug("Sending notification for issues")
    util.send(EMAIL_SUBJECT, body_text = '\n'.join(map(str, issues)))

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
    vote_parameters_mismatch_consensus,
    certificate_expiration,
    consensuses_have_same_votes,
    has_all_signatures,
    voting_bandwidth_scanners,
    has_authority_flag,
    is_recommended_versions,
    bad_exits_in_sync,
    bandwidth_authorities_in_sync,
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
    return Issue.for_msg(runlevel, 'MISSING_LATEST_CONSENSUS', ', '.join(stale_authorities))


def consensus_method_unsupported(latest_consensus, consensuses, votes):
  "Checks that all of the votes support the present consensus method."

  incompatible_authorities = []

  for authority, vote in votes.items():
    if not latest_consensus.consensus_method in vote.consensus_methods:
      incompatible_authorities.append(authority)

  if incompatible_authorities:
    return Issue.for_msg(Runlevel.WARNING, 'CONSENSUS_METHOD_UNSUPPORTED', ', '.join(incompatible_authorities))


def different_recommended_client_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for clients match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.client_versions and latest_consensus.client_versions != vote.client_versions:
      msg = _version_difference_str(authority, latest_consensus.client_versions, vote.client_versions)
      differences.append(msg)

  if differences:
    return Issue.for_msg(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', 'client', ', '.join(differences))


def different_recommended_server_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for servers match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.server_versions and latest_consensus.server_versions != vote.server_versions:
      msg = _version_difference_str(authority, latest_consensus.server_versions, vote.server_versions)
      differences.append(msg)

  if differences:
    return Issue.for_msg(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', 'server', ', '.join(differences))


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

  unknown_entries = []

  for authority, vote in votes.items():
    unknown_params = []

    for param_key, param_value in vote.params.items():
      if not param_key in CONFIG['known_params'] and not param_key.startswith('bwauth'):
        unknown_params.append('%s=%s' % (param_key, param_value))

    if unknown_params:
      unknown_entries.append('%s %s' % (authority, ' '.join(unknown_params)))

  if unknown_entries:
    return Issue.for_msg(Runlevel.NOTICE, 'UNKNOWN_CONSENSUS_PARAMETERS', ', '.join(unknown_entries))


def vote_parameters_mismatch_consensus(latest_consensus, consensuses, votes):
  "Check that all vote parameters appear in the consensus."

  mismatching_entries = []

  for authority, vote in votes.items():
    mismatching_params = []

    for param_key, param_value in vote.params.items():
      if latest_consensus.params.get(param_key) != param_value:
        mismatching_params.append('%s=%s' % (param_key, param_value))

    if mismatching_params:
      mismatching_entries.append('%s %s' % (authority, ' '.join(mismatching_params)))

  if mismatching_entries:
    return Issue.for_msg(Runlevel.NOTICE, 'MISMATCH_CONSENSUS_PARAMETERS', ', '.join(mismatching_entries))


def certificate_expiration(latest_consensus, consensuses, votes):
  "Check if an authority's certificate is about to expire."

  issues = []
  current_time = datetime.datetime.now()

  for authority, vote in votes.items():
    # votes should only have a single authority entry (the one that issued this vote)

    cert_expiration = vote.directory_authorities[0].key_certificate.expires

    if (cert_expiration - current_time) <= datetime.timedelta(days = 14):
      if rate_limit_notice('cert_expiration.two_weeks.%s' % authority, days = 14):
        issues.append(Issue.for_msg(Runlevel.WARNING, 'CERTIFICATE_ABOUT_TO_EXPIRE', 'two weeks', authority))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 60):
      if rate_limit_notice('cert_expiration.two_months.%s' % authority, days = 60):
        issues.append(Issue.for_msg(Runlevel.NOTICE, 'CERTIFICATE_ABOUT_TO_EXPIRE', 'two months', authority))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 90):
      if rate_limit_notice('cert_expiration.three_months.%s' % authority, days = 90):
        issues.append(Issue.for_msg(Runlevel.NOTICE, 'CERTIFICATE_ABOUT_TO_EXPIRE', 'three months', authority))

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
    return Issue.for_msg(Runlevel.NOTICE, 'MISSING_VOTES', ', '.join(authorities_missing_votes))


def has_all_signatures(latest_consensus, consensuses, votes):
  "Check that the consensuses have signatures for authorities that voted on it."

  missing_authorities = set()

  for consensus in consensuses.values():
    authority_signatures = set([authority.fingerprint for authority in consensus.directory_authorities])
    signature_signatures = set([sig.identity for sig in consensus.signatures])

    for missing_signature in authority_signatures.difference(signature_signatures):
      # Attempt to translate the missing v3ident signatures into authority
      # nicknames, falling back to just notifying of the v3ident if not found.

      missing_authority = missing_signature

      for authority in DIRECTORY_AUTHORITIES.values():
        if authority.v3ident == missing_signature:
          missing_authority = authority.nickname
          break

      missing_authorities.add(missing_authority)

  if missing_authorities:
    return Issue.for_msg(Runlevel.NOTICE, 'MISSING_SIGNATURE', ', '.join(missing_authorities))


def voting_bandwidth_scanners(latest_consensus, consensuses, votes):
  "Checks that we have bandwidth scanner results from the authorities that vote on it."

  missing_authorities, extra_authorities = [], []

  for authority, vote in votes.items():
    contains_measured_bandwidth = False

    for desc in vote.routers.values():
      if desc.measured:
        contains_measured_bandwidth = True
        break

    if authority in CONFIG['bandwidth_authorities'] and not contains_measured_bandwidth:
      missing_authorities.append(authority)
    if authority not in CONFIG['bandwidth_authorities'] and contains_measured_bandwidth:
      extra_authorities.append(authority)

  issues = []

  if missing_authorities:
    if rate_limit_notice('missing_bw_scanners.%s' % '.'.join(missing_authorities), days = 1):
      runlevel = Runlevel.ERROR if len(missing_authorities) > 1 else Runlevel.WARNING
      issues.append(Issue.for_msg(runlevel, 'MISSING_BANDWIDTH_SCANNERS', ', '.join(missing_authorities)))

  if extra_authorities:
    if rate_limit_notice('extra_bw_scanners.%s' % '.'.join(extra_authorities), days = 1):
      issues.append(Issue.for_msg(Runlevel.NOTICE, 'EXTRA_BANDWIDTH_SCANNERS', ', '.join(extra_authorities)))

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
    if rate_limit_notice('missing_authorities.%s' % '.'.join(missing_authorities), days = 7):
      issues.append(Issue.for_msg(Runlevel.WARNING, 'MISSING_AUTHORITIES', ', '.join(missing_authorities)))

  if extra_authorities:
    if rate_limit_notice('extra_authorities.%s' % '.'.join(extra_authorities), days = 7):
      issues.append(Issue.for_msg(Runlevel.NOTICE, 'EXTRA_AUTHORITIES', ', '.join(extra_authorities)))

  return issues


def has_expected_fingerprints(latest_consensus, consensuses, votes):
  "Checks that the authorities have the fingerprints that we expect."

  issues = []
  for desc in latest_consensus.routers.values():
    if desc.nickname in DIRECTORY_AUTHORITIES and Flag.NAMED in desc.flags:
      expected_fingerprint = DIRECTORY_AUTHORITIES[desc.nickname].fingerprint

      if desc.fingerprint != expected_fingerprint:
        issues.append(Issue.for_msg(Runlevel.ERROR, 'FINGERPRINT_MISMATCH', desc.nickname, desc.fingerprint, expected_fingerprint))

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
    if rate_limit_notice('tor_out_of_date.%s' % '.'.join(outdated_authorities.keys()), days = 7):
      entries = ['%s (%s)' % (k, v) for k, v in outdated_authorities.items()]
      return Issue.for_msg(Runlevel.WARNING, 'TOR_OUT_OF_DATE', ', '.join(entries))


def bad_exits_in_sync(latest_consensus, consensuses, votes):
  "Checks that the authorities that vote on the BadExit flag are in agreement."

  bad_exits = {}  # mapping of authorities to the fingerprints with the BadExit flag

  for authority, vote in votes.items():
    flagged = [desc.fingerprint for desc in vote.routers.values() if Flag.BADEXIT in desc.flags]

    if flagged:
      bad_exits[authority] = set(flagged)

  voting_authorities = set(bad_exits.keys())
  agreed_bad_exits = set.intersection(*bad_exits.values())
  disagreed_bad_exits = set.union(*bad_exits.values()).difference(agreed_bad_exits)

  issues = []

  for fingerprint in disagreed_bad_exits:
    with_flag = set([authority for authority, flagged in bad_exits.items() if fingerprint in flagged])
    without_flag = voting_authorities.difference(with_flag)

    issues.append(Issue.for_msg(Runlevel.NOTICE, 'BADEXIT_OUT_OF_SYNC', fingerprint, ', '.join(with_flag), ', '.join(without_flag)))

  if issues and rate_limit_notice('bad_exits_in_sync', days = 1):
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

  average = sum(measurement_counts.values()) / len(measurement_counts)

  for authority, count in measurement_counts.items():
    if count > (1.2 * average) or count < (0.8 * average):
      if rate_limit_notice('bandwidth_authorities_in_sync', days = 1):
        entries = ['%s (%s)' % (authority, count) for authority, count in measurement_counts.items()]
        return Issue.for_msg(Runlevel.NOTICE, 'BANDWIDTH_AUTHORITIES_OUT_OF_SYNC', ', '.join(entries))

      break


def get_consensuses():
  """
  Provides a mapping of directory authority nicknames to their present consensus.

  :returns: tuple of the form ({authority => consensus}, issues)
  """

  return _get_documents('consensus', '/tor/status-vote/current/consensus')


def get_votes():
  """
  Provides a mapping of directory authority nicknames to their present vote.

  :returns: tuple of the form ({authority => vote}, issues)
  """

  return _get_documents('vote', '/tor/status-vote/current/authority')


def _get_documents(label, resource):
  queries, documents, issues = {}, {}, []

  for authority in DIRECTORY_AUTHORITIES.values():
    queries[authority.nickname] = downloader.query(
      resource,
      endpoints = [(authority.address, authority.dir_port)],
      default_params = False,
    )

  for authority, query in queries.items():
    try:
      documents[authority] = query.run()[0]
    except Exception, exc:
      if label == 'vote' and authority in DIRECTORY_AUTHORITIES:
        # try to download the vote via the other authorities

        v3ident = DIRECTORY_AUTHORITIES[authority].v3ident

        if v3ident is None:
          continue  # not a voting authority

        query = downloader.query(
          '/tor/status-vote/current/%s' % v3ident,
          default_params = False,
        )

        query.run(True)

        if not query.error:
          documents[authority] = list(query)[0]
          continue

      msg = "Unable to retrieve the %s from %s (%s): %s" % (label, authority, query.download_url, exc)

      log.info(msg)
      issues.append(Issue(Runlevel.ERROR, msg))

  return documents, issues


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "consensus_health_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)
    util.send("Script Error", body_text = msg, destination = util.ERROR_ADDRESS)
