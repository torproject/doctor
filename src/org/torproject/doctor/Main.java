/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.util.*;
import org.torproject.descriptor.*;

/* Coordinate the process of downloading consensus and votes to check
 * Tor's consensus health. */
public class Main {
  public static void main(String[] args) {

    /* Download consensus and corresponding votes from the directory
     * authorities. */
    Downloader downloader = new Downloader();
    List<DescriptorRequest> downloads =
        downloader.downloadFromAuthorities();

    /* Check consensus and votes for possible problems and write warnings
     * to status files. */
    StatusFileReport statusFile = new StatusFileReport();
    Checker checker = new Checker();
    checker.processDownloadedConsensuses(downloads);
    SortedMap<Warning, String> warnings = checker.getWarnings();
    statusFile.processWarnings(warnings);
    statusFile.writeReport();

    /* Write a complete consensus-health report to an HTML file. */
    MetricsWebsiteReport website =
        new MetricsWebsiteReport("website/consensus-health.html");
    website.processDownloadedConsensuses(downloads);
    DownloadStatistics fetchStatistics = new DownloadStatistics();
    fetchStatistics.memorizeFetchTimes(downloads);
    fetchStatistics.prepareStatistics();
    website.includeFetchStatistics(fetchStatistics);
    website.writeReport();
  }
}

