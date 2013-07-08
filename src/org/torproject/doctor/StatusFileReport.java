/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.io.*;
import java.text.*;
import java.util.*;

/* Check a given consensus and votes for irregularities and write results
 * to status files while rate-limiting warnings based on severity.  There
 * will be a 'all-warnings' file with all warnings and a 'new-warnings'
 * file with only the warnings that haven't been emitted recently. */
public class StatusFileReport {

  /* Date-time format to format timestamps. */
  private static SimpleDateFormat dateTimeFormat;
  static {
    dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  /* Warnings obtained from checking the current consensus and votes. */
  private SortedMap<Warning, SortedSet<String>> warnings;
  public void processWarnings(SortedMap<Warning,
      SortedSet<String>> warnings) {
    this.warnings = warnings;
  }

  /* Write warnings to the status files. */
  public void writeReport() {
    this.readLastWarned();
    this.prepareStatusFiles();
    this.writeStatusFiles();
    this.writeLastWarned();
  }

  /* Map of warning message strings and when they were last included in
   * the 'new-warnings' file.  This map is used to implement rate
   * limiting. */
  private Map<String, Long> lastWarned = new HashMap<String, Long>();

  /* Read when we last emitted a warning to rate-limit some of them. */
  private File lastWarnedFile = new File("out/state/last-warned");
  private void readLastWarned() {
    try {
      if (this.lastWarnedFile.exists()) {
        BufferedReader br = new BufferedReader(new FileReader(
            this.lastWarnedFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (!line.contains(": ")) {
            System.err.println("Bad line in "
                + lastWarnedFile.getAbsolutePath() + ": '" + line
                + "'.  Ignoring this line.");
            continue;
          }
          long warnedMillis = Long.parseLong(line.substring(0,
              line.indexOf(": ")));
          String message = line.substring(line.indexOf(": ") + 2);
          lastWarned.put(message, warnedMillis);
        }
        br.close();
      }
    } catch (IOException e) {
      System.err.println("Could not read file '"
          + this.lastWarnedFile.getAbsolutePath() + "' to learn which "
          + "warnings have been sent out before.  Ignoring.");
    }
  }

  /* Prepare status files to be written. */
  private String allWarnings = null, newWarnings = null;
  private void prepareStatusFiles() {
    SortedMap<String, Long> warningStrings = new TreeMap<String, Long>();
    for (Map.Entry<Warning, SortedSet<String>> e :
        this.warnings.entrySet()) {
      Warning type = e.getKey();
      SortedSet<String> details = e.getValue();
      StringBuilder sb = new StringBuilder();
      int written = 0;
      for (String detail : details) {
        sb.append((written++ > 0 ? ", " : "") + detail);
      }
      String detailsString = sb.toString();
      switch (type) {
        case NoConsensusKnown:
          warningStrings.put("ERROR: No consensus known.", 0L);
          break;
        case ConsensusDownloadTimeout:
          warningStrings.put((details.size() > 3 ? "ERROR" : "WARNING")
              + ": The following directory authorities did not return a "
              + "consensus within a timeout of 60 seconds: "
              + detailsString, 150L * 60L * 1000L);
          break;
        case ConsensusNotFresh:
          warningStrings.put((details.size() > 3 ? "ERROR" : "WARNING")
              + ": The consensuses published by the following directory "
              + "authorities are more than 1 hour old and therefore not "
              + "fresh anymore: " + detailsString, 150L * 60L * 1000L);
          break;
        case ConsensusMethodNotSupported:
          warningStrings.put("WARNING: The following directory "
              + "authorities do not support the consensus method that "
              + "the consensus uses: " + detailsString,
              24L * 60L * 60L * 1000L);
          break;
        case DifferentRecommendedClientVersions:
          warningStrings.put("NOTICE: The following directory "
              + "authorities recommend other client versions than the "
              + "consensus: " + detailsString, 150L * 60L * 1000L);
          break;
        case DifferentRecommendedServerVersions:
          warningStrings.put("NOTICE: The following directory "
              + "authorities recommend other server versions than the "
              + "consensus: " + detailsString, 150L * 60L * 1000L);
          break;
        case UnknownConsensusParams:
          warningStrings.put("NOTICE: The following directory "
              + "authorities set unknown consensus parameters: "
              + detailsString, 330L * 60L * 1000L);
          break;
        case ConflictingConsensusParams:
          warningStrings.put("NOTICE: The following directory "
              + "authorities set conflicting consensus parameters: "
              + detailsString, 330L * 60L * 1000L);
          break;
        case CertificateExpiresInThreeMonths:
          warningStrings.put("NOTICE: The certificates of the following "
              + "directory authorities expire within the next three "
              + "months: " + detailsString,
              5L * 7L * 24L * 60L * 60L * 1000L);
          break;
        case CertificateExpiresInTwoMonths:
          warningStrings.put("NOTICE: The certificates of the following "
              + "directory authorities expire within the next two "
              + "months: " + detailsString, 7L * 24L * 60L * 60L * 1000L);
          break;
        case CertificateExpiresInTwoWeeks:
          warningStrings.put("WARNING: The certificates of the following "
              + "directory authorities expire within the next 14 days: "
              + detailsString, 24L * 60L * 60L * 1000L);
          break;
        case VotesMissing:
          warningStrings.put("WARNING: We're missing votes from the "
              + "following directory authorities: " + detailsString,
              150L * 60L * 1000L);
          break;
        case BandwidthScannerResultsMissing:
          warningStrings.put((details.size() > 1 ? "ERROR" : "WARNING")
              + ": The following directory authorities are not reporting "
              + "bandwidth scanner results: " + detailsString,
              150L * 60L * 1000L);
          break;
        case ConsensusMissingVotes:
          warningStrings.put("NOTICE: The consensuses downloaded from "
              + "the following authorities are missing votes that are "
              + "contained in consensuses downloaded from other "
              + "authorities: " + detailsString, 150L * 60L * 1000L);
          break;
        case ConsensusMissingSignatures:
          warningStrings.put("NOTICE: The signatures of the following, "
              + "previously voting authorities are missing from at least "
              + "one consensus: " + detailsString, 150L * 60L * 1000L);
          break;
        case MissingAuthorities:
          warningStrings.put("WARNING: The following authorities are "
              + "missing from the consensus: " + detailsString,
              150L * 60L * 1000L);
          break;
        case UnexpectedFingerprints:
          warningStrings.put("ERROR: The following relays running on the "
              + "IP address and dir port of authorities are using "
              + "different relay identity keys than expected: "
              + detailsString, 150L * 60L * 1000L);
          break;
        case UnrecommendedVersions:
            warningStrings.put("WARNING: The following authorities are "
                + "running unrecommended Tor versions: "
                + detailsString, 150L * 60L * 1000L);
            break;
      }
    }
    long now = System.currentTimeMillis();
    StringBuilder allSb = new StringBuilder(),
        newSb = new StringBuilder();
    List<String> severities = Arrays.asList(new String[] {
        "ERROR", "WARNING", "NOTICE" });
    for (String severity : severities) {
      for (Map.Entry<String, Long> e : warningStrings.entrySet()) {
        String message = e.getKey();
        if (!message.startsWith(severity)) {
          continue;
        }
        allSb.append(message + "\n");
        long warnInterval = e.getValue();
        if (!lastWarned.containsKey(message) ||
            lastWarned.get(message) + warnInterval < now) {
          newSb.append(message + "\n");
        }
      }
    }
    if (newSb.length() > 0) {
      this.allWarnings = allSb.toString();
      this.newWarnings = newSb.toString();
      for (String message : warningStrings.keySet()) {
        this.lastWarned.put(message, now);
      }
    }
  }

  /* Write status files to disk. */
  private File allWarningsFile = new File("out/status/all-warnings");
  private File newWarningsFile = new File("out/status/new-warnings");
  private void writeStatusFiles() {
    try {
      this.allWarningsFile.getParentFile().mkdirs();
      this.newWarningsFile.getParentFile().mkdirs();
      BufferedWriter allBw = new BufferedWriter(new FileWriter(
          this.allWarningsFile));
      BufferedWriter newBw = new BufferedWriter(new FileWriter(
          this.newWarningsFile));
      if (this.allWarnings != null) {
        allBw.write(this.allWarnings);
      }
      if (this.newWarnings != null) {
        newBw.write(this.newWarnings);
      }
      allBw.close();
      newBw.close();
    } catch (IOException e) {
      System.err.println("Could not write status files '"
          + this.allWarningsFile.getAbsolutePath() + "' and/or '"
          + this.newWarningsFile.getAbsolutePath() + "'.  Ignoring.");
    }
  }

  /* Write timestamps when warnings were last sent to disk. */
  private void writeLastWarned() {
    try {
      this.lastWarnedFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.lastWarnedFile));
      for (Map.Entry<String, Long> e : lastWarned.entrySet()) {
        bw.write(String.valueOf(e.getValue()) + ": " + e.getKey() + "\n");
      }
      bw.close();
    } catch (IOException e) {
      System.err.println("Could not write file '"
          + this.lastWarnedFile.getAbsolutePath() + "' to remember which "
          + "warnings have been sent out before.  Ignoring.");
    }
  }
}

