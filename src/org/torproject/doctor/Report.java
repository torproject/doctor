/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.util.*;

/* Transform findings from parsing consensuses and votes into a report of
 * some form. */
public interface Report {

  /* Process the downloaded current consensus and corresponding votes to
   * find irregularities between them. */
  public abstract void processDownloadedConsensuses(
      SortedMap<String, Status> downloadedConsensuses);

  /* Process warnings consisting of warning type and details. */
  public abstract void processWarnings(
      SortedMap<Warning, String> warnings);

  /* Include download statistics. */
  public abstract void includeFetchStatistics(
      DownloadStatistics statistics);

  /* Finish writing report. */
  public abstract void writeReport();
}

