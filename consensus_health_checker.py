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
import stem.util.enum

Runlevel = stem.util.enum.UppercaseEnum("NOTICE", "WARNING", "ERROR")

EMAIL_SUBJECT = 'Consensus issues'

KNOWN_PARAMS = (
  'bwweightscale',
  'circwindow',
  'CircuitPriorityHalflifeMsec',
  'refuseunknownexits',
  'cbtdisabled',
  'cbtnummodes',
  'cbtrecentcount',
  'cbtmaxtimeouts',
  'cbtmincircs',
  'cbtquantile',
  'cbtclosequantile',
  'cbttestfreq',
  'cbtmintimeout',
  'cbtinitialtimeout',
  'perconnbwburst',
  'perconnbwrate',
  'UseOptimisticData',
  'pb_disablepct',
  'UseNTorHandshake',
)

MISSING_LATEST_CONSENSUS_MSG = """\
The consensuses published by the following directory authorities are more than \
one hour old and therefore not fresh anymore: %s"""

CONSENSUS_METHOD_UNSUPPORTED_MSG = """\
The following directory authorities do not support the consensus method that \
the consensus uses: %s"""

DIFFERENT_RECOMMENDED_VERSION_MSG = """\
The following directory authorities recommend other %s versions than the \
consensus: %s"""

UNKNOWN_CONSENSUS_PARAMETERS_MSG = """\
The following directory authorities set unknown consensus parameters: %s"""

MISMATCH_CONSENSUS_PARAMETERS_MSG = """\
The following directory authorities set conflicting consensus parameters: %s"""

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

  def __str__(self):
    return "%s: %s" % (self.runlevel, self.msg)


def main():
  start_time = time.time()

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

    my_check(latest_consensus, consensuses, votes) => Issue

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
  )

  issues = []

  for checker in checker_functions:
    issue = checker(latest_consensus, consensuses, votes)

    if issue:
      log.debug(issue)
      issues.append(issue)

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
    return Issue(runlevel, MISSING_LATEST_CONSENSUS_MSG % ', '.join(stale_authorities))


def consensus_method_unsupported(latest_consensus, consensuses, votes):
  "Checks that all of the votes support the present consensus method."

  incompatable_authorities = []

  for authority, vote in votes.items():
    if not latest_consensus.consensus_method in vote.consensus_methods:
      incompatable_authorities.append(authority)

  if incompatable_authorities:
    return Issue(Runlevel.WARNING, CONSENSUS_METHOD_UNSUPPORTED_MSG % ', '.join(incompatable_authorities))


def different_recommended_client_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for clients match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.client_versions and latest_consensus.client_versions != vote.client_versions:
      msg = _version_difference_str(authority, latest_consensus.client_versions, vote.client_versions)
      differences.append(msg)

  if differences:
    return Issue(Runlevel.NOTICE, DIFFERENT_RECOMMENDED_VERSION_MSG % ('client', ', '.join(differences)))


def different_recommended_server_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for servers match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.server_versions and latest_consensus.server_versions != vote.server_versions:
      msg = _version_difference_str(authority, latest_consensus.server_versions, vote.server_versions)
      differences.append(msg)

  if differences:
    return Issue(Runlevel.NOTICE, DIFFERENT_RECOMMENDED_VERSION_MSG % ('server', ', '.join(differences)))


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
      if not param_key in KNOWN_PARAMS and not param_key.startswith('bwauth'):
        unknown_params.append('%s=%s' % (param_key, param_value))

    if unknown_params:
      unknown_entries.append('%s %s' % (authority, ' '.join(unknown_params)))

  if unknown_entries:
    return Issue(Runlevel.NOTICE, UNKNOWN_CONSENSUS_PARAMETERS_MSG % ', '.join(unknown_entries))


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
    return Issue(Runlevel.NOTICE, MISMATCH_CONSENSUS_PARAMETERS_MSG % ', '.join(mismatching_entries))


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
      documents[authority] = list(query)[0]
    except Exception, exc:
      msg = "Unable to retrieve the %s from %s (%s): %s" % (label, authority, query.download_url, exc)

      log.info(msg)
      issues.append(Issue(Runlevel.ERROR, msg))

  return documents, issues


if __name__ == '__main__':
  try:
    main()
  except:
    log.error("Script failed:\n%s" % traceback.format_exc())
