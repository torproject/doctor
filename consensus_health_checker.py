#!/usr/bin/env python

"""
Performs a variety of checks against the present votes and consensus, similar
to DocTor (https://gitweb.torproject.org/doctor.git).
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
    config.load(config_path)
  except:
    pass

  current_time = int(time.time())
  last_seen = config.get(key, 0)
  suppression_time = (3600 * hours) + (86400 * days)
  suppression_time_remaining = suppression_time - (current_time - last_seen)

  if suppression_time_remaining <= 0:
    config.set(key, str(current_time), overwrite = True)
    config.save(config_path)
    return True
  else:
    log.info("Suppressing %s, time remaining is %is" % (key, suppression_time_remaining))
    return False


def main():
  start_time = time.time()

  # loads configuration data

  config = stem.util.conf.get_config("consensus_health")
  config.load(util.get_path('data', 'consensus_health.cfg'))

  # Downloading the consensus and vote from all authorities, then running our
  # checks over them. If we fail to download a consensus then we skip
  # downloading a vote from that authority. If all votes can't be fetched then
  # our checks are skipped.

  consensuses, consensus_fetching_issues = get_consensuses()
  votes, vote_fetching_issues = get_votes(consensuses.keys())
  issues = consensus_fetching_issues + vote_fetching_issues

  if votes:
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
    unknown_consensus_parameteres,
    vote_parameters_mismatch_consensus,
    certificate_expiration,
    voting_bandwidth_scanners,
    has_authority_flag,
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

  return issues


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

  incompatable_authorities = []

  for authority, vote in votes.items():
    if not latest_consensus.consensus_method in vote.consensus_methods:
      incompatable_authorities.append(authority)

  if incompatable_authorities:
    return Issue.for_msg(Runlevel.WARNING, 'CONSENSUS_METHOD_UNSUPPORTED', ', '.join(incompatable_authorities))


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


def unknown_consensus_parameteres(latest_consensus, consensuses, votes):
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

    if len(vote.directory_authorities) != 1:
      issues.append(Issue.for_msg(Runlevel.WARNING, 'VOTE_HAS_MULTIPLE_AUTHORITIES', authority, vote))
      continue

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
    runlevel = Runlevel.ERROR if len(missing_authorities) > 1 else Runlevel.WARNING
    issues.append(Issue.for_msg(runlevel, 'MISSING_BANDWIDTH_SCANNERS', ', '.join(missing_authorities)))

  if extra_authorities:
    issues.append(Issue.for_msg(Runlevel.NOTICE, 'EXTRA_BANDWIDTH_SCANNERS', ', '.join(extra_authorities)))

  return issues


def has_authority_flag(latest_consensus, consensuses, votes):
  "Checks that the authorities have the 'authority' flag in the present consensus."

  seen_authorities = set()

  for desc in latest_consensus.routers.values():
    if Flag.AUTHORITY in desc.flags:
      seen_authorities.add(desc.nickname)

  # Tonga lacks a v3ident so the remote descriptor module doesn't include it,
  # but it's still an authority.

  known_authorities = set(stem.descriptor.remote.DIRECTORY_AUTHORITIES.keys())
  known_authorities.add('Tonga')

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


def get_consensuses(authorities = None):
  """
  Provides a mapping of directory authority nicknames to their present consensus.

  :param list authorities: optional list of authority nicknames, if present
    then only these authorities will be queried

  :returns: tuple of the form ({authority => consensus}, issues)
  """

  return _get_documents(authorities, 'consensus', '/tor/status-vote/current/consensus')


def get_votes(authorities = None):
  """
  Provides a mapping of directory authority nicknames to their present vote.

  :param list authorities: optional list of authority nicknames, if present
    then only these authorities will be queried

  :returns: tuple of the form ({authority => vote}, issues)
  """

  return _get_documents(authorities, 'vote', '/tor/status-vote/current/authority')


def _get_documents(authorities, label, resource):
  queries, documents, issues = {}, {}, []

  for authority, endpoint in stem.descriptor.remote.DIRECTORY_AUTHORITIES.items():
    if authorities is not None and not authority in authorities:
      continue

    queries[authority] = downloader.query(
      resource,
      endpoints = [endpoint],
      default_params = False,
    )

  for authority, query in queries.items():
    try:
      documents[authority] = query.run()[0]
    except Exception, exc:
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
    util.send("Script Error", body_text = msg)
