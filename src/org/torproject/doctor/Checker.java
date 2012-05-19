/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.io.*;
import java.text.*;
import java.util.*;
import org.torproject.descriptor.*;

/* Check a given consensus and votes for irregularities and write results
 * to a warnings map consisting of warning type and details. */
public class Checker {

  /* Warning messages consisting of type and details. */
  private SortedMap<Warning, SortedSet<String>> warnings =
      new TreeMap<Warning, SortedSet<String>>();
  public SortedMap<Warning, SortedSet<String>> getWarnings() {
    return this.warnings;
  }

  /* Date-time format to format timestamps. */
  private static SimpleDateFormat dateTimeFormat;
  static {
    dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  /* Check consensuses and votes. */
  public void processDownloadedConsensuses(
      List<DescriptorRequest> downloads) {
    this.storeDownloads(downloads);
    this.findMostRecentConsensus();
    this.checkMissingConsensuses();
    this.checkAllConsensusesFresh();
    this.checkContainedVotes();
    this.checkConsensusSignatures();
    if (this.downloadedConsensus != null) {
      if (this.isConsensusFresh(this.downloadedConsensus)) {
        this.checkConsensusMethods();
        this.checkRecommendedVersions();
        this.checkConsensusParameters();
        this.checkAuthorityKeys();
        this.checkMissingVotes();
        this.checkBandwidthScanners();
        this.checkMissingAuthorities();
      }
    } else {
      this.warnings.put(Warning.NoConsensusKnown, new TreeSet<String>());
    }
  }

  /* Store consensuses and votes in a way that we can process them more
   * easily. */
  private SortedMap<String, RelayNetworkStatusConsensus>
      downloadedConsensuses = new TreeMap<String,
      RelayNetworkStatusConsensus>();
  private RelayNetworkStatusConsensus downloadedConsensus;
  private List<RelayNetworkStatusVote> downloadedVotes =
      new ArrayList<RelayNetworkStatusVote>();
  private void storeDownloads(List<DescriptorRequest> downloads) {
    for (DescriptorRequest request : downloads) {
      if (request.getDescriptors() == null) {
        continue;
      }
      for (Descriptor descriptor : request.getDescriptors()) {
        if (descriptor instanceof RelayNetworkStatusConsensus) {
          this.downloadedConsensuses.put(request.getDirectoryNickname(),
              (RelayNetworkStatusConsensus) descriptor);
        } else if (descriptor instanceof RelayNetworkStatusVote) {
          this.downloadedVotes.add((RelayNetworkStatusVote) descriptor);
        } else {
          System.err.println("Did not expect a descriptor of type "
              + descriptor.getClass() + ".  Ignoring.");
        }
      }
    }
  }

  /* Find most recent consensus and corresponding votes. */
  private void findMostRecentConsensus() {
    long mostRecentValidAfterMillis = -1L;
    for (RelayNetworkStatusConsensus downloadedConsensus :
        downloadedConsensuses.values()) {
      if (downloadedConsensus.getValidAfterMillis() >
          mostRecentValidAfterMillis) {
        this.downloadedConsensus = downloadedConsensus;
        mostRecentValidAfterMillis =
            downloadedConsensus.getValidAfterMillis();
      }
    }
  }

  /* Check if any directory authority didn't tell us a consensus. */
  private void checkMissingConsensuses() {
    SortedSet<String> missingConsensuses = new TreeSet<String>(
        Arrays.asList(("gabelmoo,tor26,turtles,maatuska,dannenberg,urras,"
        + "moria1,dizum").split(",")));
    missingConsensuses.removeAll(this.downloadedConsensuses.keySet());
    if (!missingConsensuses.isEmpty()) {
      this.warnings.put(Warning.ConsensusDownloadTimeout,
          missingConsensuses);
    }
  }

  /* Check if all consensuses are fresh. */
  private void checkAllConsensusesFresh() {
    long fresh = System.currentTimeMillis() - 60L * 60L * 1000L;
    SortedSet<String> nonFresh = new TreeSet<String>();
    for (Map.Entry<String, RelayNetworkStatusConsensus> e :
        downloadedConsensuses.entrySet()) {
      String nickname = e.getKey();
      RelayNetworkStatusConsensus downloadedConsensus = e.getValue();
      if (downloadedConsensus.getValidAfterMillis() < fresh) {
        nonFresh.add(nickname);
      }
    }
    if (!nonFresh.isEmpty()) {
      this.warnings.put(Warning.ConsensusNotFresh, nonFresh);
    }
  }

  /* Check if all downloaded consensuses contain the same set of votes. */
  private void checkContainedVotes() {
    Set<String> allVotes = new HashSet<String>();
    for (RelayNetworkStatusConsensus consensus :
        downloadedConsensuses.values()) {
      allVotes.addAll(consensus.getDirSourceEntries().keySet());
    }
    SortedSet<String> missingVotes = new TreeSet<String>();
    for (Map.Entry<String, RelayNetworkStatusConsensus> e :
        downloadedConsensuses.entrySet()) {
      String nickname = e.getKey();
      RelayNetworkStatusConsensus downloadedConsensus = e.getValue();
      if (!downloadedConsensus.getDirSourceEntries().keySet().containsAll(
          allVotes)) {
        missingVotes.add(nickname);
      }
    }
    if (!missingVotes.isEmpty()) {
      this.warnings.put(Warning.ConsensusMissingVotes, missingVotes);
    }
  }

  /* Check if all downloaded consensuses contain signatures from all other
   * authorities. */
  private void checkConsensusSignatures() {
    SortedSet<String> missingSignatures = new TreeSet<String>();
    for (Map.Entry<String, RelayNetworkStatusConsensus> e :
        downloadedConsensuses.entrySet()) {
      String nickname = e.getKey();
      RelayNetworkStatusConsensus downloadedConsensus = e.getValue();
      if (!downloadedConsensus.getDirectorySignatures().keySet().
          containsAll(downloadedConsensus.getDirSourceEntries().
          keySet())) {
        missingSignatures.add(nickname);
      }
    }
    if (!missingSignatures.isEmpty()) {
      this.warnings.put(Warning.ConsensusMissingSignatures,
          missingSignatures);
    }
  }

  /* Check if the most recent consensus is older than 1 hour. */
  private boolean isConsensusFresh(
      RelayNetworkStatusConsensus consensus) {
    return (consensus.getValidAfterMillis() >=
        System.currentTimeMillis() - 60L * 60L * 1000L);
  }

  /* Check supported consensus methods of all votes. */
  private void checkConsensusMethods() {
    SortedSet<String> dirs = new TreeSet<String>();
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      if (!vote.getConsensusMethods().contains(
          this.downloadedConsensus.getConsensusMethod())) {
        dirs.add(vote.getNickname());
      }
    }
    if (!dirs.isEmpty()) {
      this.warnings.put(Warning.ConsensusMethodNotSupported, dirs);
    }
  }

  /* Check if the recommended versions in a vote are different from the
   * recommended versions in the consensus. */
  private void checkRecommendedVersions() {
    SortedSet<String> unrecommendedClientVersions = new TreeSet<String>(),
        unrecommendedServerVersions = new TreeSet<String>();
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      if (vote.getRecommendedClientVersions() != null &&
          !downloadedConsensus.getRecommendedClientVersions().equals(
          vote.getRecommendedClientVersions())) {
        StringBuilder message = new StringBuilder();
        message.append(vote.getNickname());
        for (String version : vote.getRecommendedClientVersions()) {
          message.append(" " + version);
        }
        unrecommendedClientVersions.add(message.toString());
      }
      if (vote.getRecommendedServerVersions() != null &&
          !downloadedConsensus.getRecommendedServerVersions().equals(
          vote.getRecommendedServerVersions())) {
        StringBuilder message = new StringBuilder();
        message.append(vote.getNickname());
        for (String version : vote.getRecommendedServerVersions()) {
          message.append(" " + version);
        }
        unrecommendedServerVersions.add(message.toString());
      }
    }
    if (!unrecommendedServerVersions.isEmpty()) {
      this.warnings.put(Warning.DifferentRecommendedServerVersions,
          unrecommendedServerVersions);
    }
    if (!unrecommendedClientVersions.isEmpty()) {
      this.warnings.put(Warning.DifferentRecommendedClientVersions,
          unrecommendedClientVersions);
    }
  }

  /* Check if a vote contains conflicting or invalid consensus
   * parameters. */
  private void checkConsensusParameters() {
    Set<String> validParameters = new HashSet<String>(Arrays.asList(
        ("circwindow,CircuitPriorityHalflifeMsec,refuseunknownexits,"
        + "cbtdisabled,cbtnummodes,cbtrecentcount,cbtmaxtimeouts,"
        + "cbtmincircs,cbtquantile,cbtclosequantile,cbttestfreq,"
        + "cbtmintimeout,cbtinitialtimeout,perconnbwburst,perconnbwrate").
        split(",")));
    SortedSet<String> conflicts = new TreeSet<String>();
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      Map<String, Integer> voteConsensusParams =
          vote.getConsensusParams();
      boolean conflictOrInvalid = false;
      if (voteConsensusParams != null) {
        for (Map.Entry<String, Integer> e :
            voteConsensusParams.entrySet()) {
          if (!downloadedConsensus.getConsensusParams().containsKey(
              e.getKey()) ||
              !downloadedConsensus.getConsensusParams().get(e.getKey()).
              equals(e.getValue()) ||
              (!validParameters.contains(e.getKey()) &&
              !e.getKey().startsWith("bwauth"))) {
            StringBuilder message = new StringBuilder();
            message.append(vote.getNickname());
            for (Map.Entry<String, Integer> p :
                voteConsensusParams.entrySet()) {
              message.append(" " + p.getKey() + "=" + p.getValue());
            }
            conflicts.add(message.toString());
            break;
          }
        }
      }
    }
    if (!conflicts.isEmpty()) {
      this.warnings.put(Warning.ConflictingOrInvalidConsensusParams,
          conflicts);
    }
  }

  /* Check whether any of the authority keys expire in the next 14
   * days. */
  private void checkAuthorityKeys() {
    SortedMap<String, String> certificatesExpiringInThreeMonths =
        new TreeMap<String, String>();
    SortedMap<String, String> certificatesExpiringInTwoMonths =
        new TreeMap<String, String>();
    SortedMap<String, String> certificatesExpiringInTwoWeeks =
        new TreeMap<String, String>();
    long now = System.currentTimeMillis();
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      long voteDirKeyExpiresMillis = vote.getDirKeyExpiresMillis();
      if (voteDirKeyExpiresMillis - 14L * 24L * 60L * 60L * 1000L < now) {
        certificatesExpiringInTwoWeeks.put(vote.getNickname(),
            dateTimeFormat.format(voteDirKeyExpiresMillis));
      } else if (voteDirKeyExpiresMillis - 60L * 24L * 60L * 60L * 1000L <
          now) {
        certificatesExpiringInTwoMonths.put(vote.getNickname(),
            dateTimeFormat.format(voteDirKeyExpiresMillis));
      } else if (voteDirKeyExpiresMillis - 90L * 24L * 60L * 60L * 1000L <
          now) {
        certificatesExpiringInThreeMonths.put(vote.getNickname(),
            dateTimeFormat.format(voteDirKeyExpiresMillis));
      }
    }
    if (!certificatesExpiringInThreeMonths.isEmpty()) {
      this.warnAboutExpiringCertificates(
          Warning.CertificateExpiresInThreeMonths,
          certificatesExpiringInThreeMonths);
    }
    if (!certificatesExpiringInTwoMonths.isEmpty()) {
      this.warnAboutExpiringCertificates(
          Warning.CertificateExpiresInTwoMonths,
          certificatesExpiringInTwoMonths);
    }
    if (!certificatesExpiringInTwoWeeks.isEmpty()) {
      this.warnAboutExpiringCertificates(
          Warning.CertificateExpiresInTwoWeeks,
          certificatesExpiringInTwoWeeks);
    }
  }

  private void warnAboutExpiringCertificates(Warning warningType,
      SortedMap<String, String> expiringCertificates) {
    SortedSet<String> details = new TreeSet<String>();
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e :
        expiringCertificates.entrySet()) {
      String dir = e.getKey();
      String timestamp = e.getValue();
      details.add(dir + " " + timestamp);
    }
    this.warnings.put(warningType, details);
  }

  /* Check if any votes are missing. */
  private void checkMissingVotes() {
    SortedSet<String> knownAuthorities = new TreeSet<String>(
        Arrays.asList(("dannenberg,dizum,gabelmoo,turtles,maatuska,"
        + "moria1,tor26,urras").split(",")));
    SortedSet<String> missingVotes =
        new TreeSet<String>(knownAuthorities);
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      missingVotes.remove(vote.getNickname());
    }
    if (!missingVotes.isEmpty()) {
      this.warnings.put(Warning.VotesMissing, missingVotes);
    }
  }

  /* Check if any bandwidth scanner results are missing. */
  private void checkBandwidthScanners() {
    SortedSet<String> missingBandwidthScanners = new TreeSet<String>(
        Arrays.asList("turtles,urras,moria1,gabelmoo,maatuska".
        split(",")));
    for (RelayNetworkStatusVote vote : this.downloadedVotes) {
      boolean containsMeasuredBandwidths = false;
      for (NetworkStatusEntry entry : vote.getStatusEntries().values()) {
        if (entry.getMeasured() >= 0) {
          containsMeasuredBandwidths = true;
          break;
        }
      }
      if (containsMeasuredBandwidths) {
        missingBandwidthScanners.remove(vote.getNickname());
      }
    }
    if (!missingBandwidthScanners.isEmpty()) {
      this.warnings.put(Warning.BandwidthScannerResultsMissing,
          missingBandwidthScanners);
    }
  }

  /* Check if any relays with the Authority flag are missing from the
   * consensus. */
  private void checkMissingAuthorities() {
    SortedSet<String> missingAuthorities = new TreeSet<String>(
        Arrays.asList(("gabelmoo,tor26,turtles,maatuska,dannenberg,urras,"
        + "moria1,dizum,Tonga").split(",")));
    for (NetworkStatusEntry entry :
        this.downloadedConsensus.getStatusEntries().values()) {
      if (entry.getFlags().contains("Authority")) {
        missingAuthorities.remove(entry.getNickname());
      }
    }
    if (!missingAuthorities.isEmpty()) {
      this.warnings.put(Warning.MissingAuthorities, missingAuthorities);
    }
  }
}

