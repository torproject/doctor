#!/usr/bin/env python
# Copyright 2013, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Performs a variety of checks against the present votes and consensus.
"""

import datetime
import subprocess
import time
import traceback

import util

import stem.descriptor
import stem.descriptor.remote
import stem.util.conf
import stem.util.enum

from stem import Flag
from stem.util.lru_cache import lru_cache

# Set this flag to print results rather than email them.

TEST_RUN = False

Runlevel = stem.util.enum.UppercaseEnum("NOTICE", "WARNING", "ERROR")

DIRECTORY_AUTHORITIES = stem.descriptor.remote.get_authorities()
EMAIL_SUBJECT = 'Consensus issues'

CONFIG = stem.util.conf.config_dict('consensus_health', {
  'msg': {},
  'suppression': {},
  'ignored_authorities': [],
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
  """

  def __init__(self, runlevel, template, **attr):
    self._runlevel = runlevel
    self._template = template
    self._attr = attr

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


@lru_cache()
def directory_authorities():
  return dict((k, v) for (k, v) in DIRECTORY_AUTHORITIES.items() if k not in CONFIG['ignored_authorities'])


def main():
  start_time = time.time()

  if not TEST_RUN:
    # Spawning a shell to run mail. We're doing this early because
    # subprocess.Popen() calls fork which doubles the memory usage of our
    # process. Hence we risk an OOM if this is done after loading gobs of
    # descriptor data into memory.

    mail_process = subprocess.Popen(
      ['mail', '-E', '-s', EMAIL_SUBJECT, util.TO_ADDRESS],
      stdin = subprocess.PIPE,
      stdout = subprocess.PIPE,
      stderr = subprocess.PIPE,
    )

    bot_notice_process = subprocess.Popen(
      ['mail', '-E', '-s', 'Announce or', 'tor-misc@commit.noreply.org'],
      stdin = subprocess.PIPE,
      stdout = subprocess.PIPE,
      stderr = subprocess.PIPE,
    )

  # loads configuration data

  config = stem.util.conf.get_config("consensus_health")
  config.load(util.get_path('data', 'consensus_health.cfg'))

  config = stem.util.conf.get_config('last_notified')
  config.load(util.get_path('data', 'last_notified.cfg'))

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
    log.debug("Sending notification for issues")

    for issue in issues:
      rate_limit_notice(issue)

    if TEST_RUN:
      print '\n'.join(map(str, issues))
    else:
      stdout, stderr = mail_process.communicate('\n'.join(map(str, issues)))
      exit_code = mail_process.poll()

      if exit_code != 0:
        raise ValueError("Unable to send email: %s" % stderr.strip())

      # notification for #tor-bots

      stdout, stderr = bot_notice_process.communicate('\n'.join(['[consensus-health] %s' % issue for issue in issues]))
      exit_code = mail_process.poll()

      if exit_code != 0:
        raise ValueError("Unable to send email: %s" % stderr.strip())
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
    vote_parameters_mismatch_consensus,
    certificate_expiration,
    consensuses_have_same_votes,
    has_all_signatures,
    voting_bandwidth_scanners,
    #unmeasured_relays,
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
    return Issue(runlevel, 'MISSING_LATEST_CONSENSUS', authorities = ', '.join(stale_authorities))


def consensus_method_unsupported(latest_consensus, consensuses, votes):
  "Checks that all of the votes support the present consensus method."

  incompatible_authorities = []

  for authority, vote in votes.items():
    if not latest_consensus.consensus_method in vote.consensus_methods:
      incompatible_authorities.append(authority)

  if incompatible_authorities:
    return Issue(Runlevel.WARNING, 'CONSENSUS_METHOD_UNSUPPORTED', authorities = ', '.join(incompatible_authorities))


def different_recommended_client_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for clients match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.client_versions and latest_consensus.client_versions != vote.client_versions:
      msg = _version_difference_str(authority, latest_consensus.client_versions, vote.client_versions)
      differences.append(msg)

  if differences:
    return Issue(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', type = 'client', differences = ', '.join(differences))


def different_recommended_server_version(latest_consensus, consensuses, votes):
  "Checks that the recommended tor versions for servers match the present consensus."

  differences = []

  for authority, vote in votes.items():
    if vote.server_versions and latest_consensus.server_versions != vote.server_versions:
      msg = _version_difference_str(authority, latest_consensus.server_versions, vote.server_versions)
      differences.append(msg)

  if differences:
    return Issue(Runlevel.NOTICE, 'DIFFERENT_RECOMMENDED_VERSION', type = 'server', differences = ', '.join(differences))


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
    return Issue(Runlevel.NOTICE, 'UNKNOWN_CONSENSUS_PARAMETERS', parameters = ', '.join(unknown_entries))


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
    return Issue(Runlevel.NOTICE, 'MISMATCH_CONSENSUS_PARAMETERS', parameters = ', '.join(mismatching_entries))


def certificate_expiration(latest_consensus, consensuses, votes):
  "Check if an authority's certificate is about to expire."

  issues = []
  current_time = datetime.datetime.now()

  for authority, vote in votes.items():
    # votes should only have a single authority entry (the one that issued this vote)

    cert_expiration = vote.directory_authorities[0].key_certificate.expires
    expiration_label = '%s (%s)' % (authority, cert_expiration.strftime('%Y-%m-%d %H-%M-%S'))

    if (cert_expiration - current_time) <= datetime.timedelta(days = 7):
      issues.append(Issue(Runlevel.WARNING, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'week', authority = expiration_label))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 14):
      issues.append(Issue(Runlevel.WARNING, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'two weeks', authority = expiration_label))
    elif (cert_expiration - current_time) <= datetime.timedelta(days = 21):
      issues.append(Issue(Runlevel.NOTICE, 'CERTIFICATE_ABOUT_TO_EXPIRE', duration = 'three weeks', authority = expiration_label))

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
    return Issue(Runlevel.NOTICE, 'MISSING_VOTES', authorities = ', '.join(authorities_missing_votes))


def has_all_signatures(latest_consensus, consensuses, votes):
  "Check that the consensuses have signatures for authorities that voted on it."

  issues = []

  for consensus_of, consensus in consensuses.items():
    voting_authorities = set([authority.fingerprint for authority in consensus.directory_authorities])
    signing_authorities = set([sig.identity for sig in consensus.signatures])
    missing_authorities = set()

    for missing_signature in voting_authorities.difference(signing_authorities):
      # Attempt to translate the missing v3ident signatures into authority
      # nicknames, falling back to just notifying of the v3ident if not found.

      missing_authority = missing_signature

      for authority in directory_authorities().values():
        if authority.v3ident == missing_signature:
          missing_authority = authority.nickname
          break

      missing_authorities.add(missing_authority)

    if missing_authorities:
      issues.append(Issue(Runlevel.NOTICE, 'MISSING_SIGNATURE', consensus_of = consensus_of, authorities = ', '.join(missing_authorities)))

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
    issues.append(Issue(runlevel, 'MISSING_BANDWIDTH_SCANNERS', authorities = ', '.join(missing_authorities)))

  if extra_authorities:
    issues.append(Issue(Runlevel.NOTICE, 'EXTRA_BANDWIDTH_SCANNERS', authorities = ', '.join(extra_authorities)))

  return issues


def unmeasured_relays(latest_consensus, consensuses, votes):
  "Checks that the bandwidth authorities have all formed an opinion about at least 90% of the relays."

  issues = []
  consensus_fingerprints = set([desc.fingerprint for desc in latest_consensus.routers.values()])

  for authority, vote in votes.items():
    if authority in CONFIG['bandwidth_authorities']:
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
        issues.append(Issue(Runlevel.NOTICE, 'TOO_MANY_UNMEASURED_RELAYS', authority = authority, unmeasured = unmeasured, total = total, percentage = percentage))

  return issues


def has_authority_flag(latest_consensus, consensuses, votes):
  "Checks that the authorities have the 'authority' flag in the present consensus."

  seen_authorities = set()

  for desc in latest_consensus.routers.values():
    if Flag.AUTHORITY in desc.flags:
      seen_authorities.add(desc.nickname)

  known_authorities = set(directory_authorities().keys())
  missing_authorities = known_authorities.difference(seen_authorities)
  extra_authorities = seen_authorities.difference(known_authorities) - set(CONFIG['ignored_authorities'])

  issues = []

  if missing_authorities:
    issues.append(Issue(Runlevel.WARNING, 'MISSING_AUTHORITIES', authorities = ', '.join(missing_authorities)))

  if extra_authorities:
    issues.append(Issue(Runlevel.NOTICE, 'EXTRA_AUTHORITIES', authorities = ', '.join(extra_authorities)))

  return issues


def has_expected_fingerprints(latest_consensus, consensuses, votes):
  "Checks that the authorities have the fingerprints that we expect."

  issues = []
  for desc in latest_consensus.routers.values():
    if desc.nickname in directory_authorities() and Flag.NAMED in desc.flags:
      expected_fingerprint = directory_authorities()[desc.nickname].fingerprint

      if desc.fingerprint != expected_fingerprint:
        issues.append(Issue(Runlevel.ERROR, 'FINGERPRINT_MISMATCH', authority = desc.nickname, expected = desc.fingerprint, actual = expected_fingerprint))

  return issues


def is_recommended_versions(latest_consensus, consensuses, votes):
  "Checks that the authorities are running a recommended version or higher."

  outdated_authorities = {}
  min_version = min(latest_consensus.server_versions)

  for authority in directory_authorities().values():
    desc = latest_consensus.routers.get(authority.fingerprint)

    if desc and desc.version and desc.version < min_version:
      outdated_authorities[authority.nickname] = desc.version

  if outdated_authorities:
    entries = ['%s (%s)' % (k, v) for k, v in outdated_authorities.items()]
    return Issue(Runlevel.WARNING, 'TOR_OUT_OF_DATE', authorities = ', '.join(entries))


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
    without_flag = voting_authorities.difference(with_flag)

    issues.append(Issue(Runlevel.NOTICE, 'BADEXIT_OUT_OF_SYNC', fingerprint = fingerprint, with_flag = ', '.join(with_flag), without_flag = ', '.join(without_flag)))

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
      return Issue(Runlevel.NOTICE, 'BANDWIDTH_AUTHORITIES_OUT_OF_SYNC', authorities = ', '.join(entries))


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

  for authority in directory_authorities().values():
    if authority.v3ident is None:
      continue  # not a voting authority

    queries[authority.nickname] = downloader.query(
      resource,
      endpoints = [(authority.address, authority.dir_port)],
      default_params = False,
    )

  for authority, query in queries.items():
    try:
      documents[authority] = query.run()[0]
    except Exception, exc:
      if label == 'vote':
        # try to download the vote via the other authorities

        v3ident = directory_authorities()[authority].v3ident

        query = downloader.query(
          '/tor/status-vote/current/%s' % v3ident,
          default_params = False,
        )

        query.run(True)

        if not query.error:
          documents[authority] = list(query)[0]
          continue

      issues.append(Issue(Runlevel.ERROR, 'AUTHORITY_UNAVAILABLE', fetch_type = label, authority = authority, url = query.download_url, error = exc))

  return documents, issues


if __name__ == '__main__':
  try:
    main()
  except:
    msg = "consensus_health_checker.py failed with:\n\n%s" % traceback.format_exc()
    log.error(msg)

    if TEST_RUN:
      print "Error: %s" % msg
    else:
      util.send("Script Error", body_text = msg, destination = util.ERROR_ADDRESS)
