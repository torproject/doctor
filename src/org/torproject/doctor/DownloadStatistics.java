/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.io.*;
import java.util.*;
import org.torproject.descriptor.*;

public class DownloadStatistics {
  public void memorizeFetchTimes(List<DescriptorRequest> downloads) {
    try {
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.statisticsFile, true));
      for (DescriptorRequest request : downloads) {
        for (Descriptor descriptor : request.getDescriptors()) {
          if (descriptor instanceof RelayNetworkStatusConsensus) {
            String authority = request.getDirectoryNickname();
            long requestStartMillis = request.getRequestStart();
            long fetchTimeMillis = request.getRequestEnd()
                - request.getRequestStart();
            String line = authority + ","
                + String.valueOf(requestStartMillis) + ","
                + String.valueOf(fetchTimeMillis);
            bw.write(line + "\n");
          }
        }
      }
      bw.close();
    } catch (IOException e) {
      System.err.println("Could not write "
          + this.statisticsFile.getAbsolutePath() + ".  Ignoring.");
    }
  }
  private SortedMap<String, List<Long>> downloadData =
      new TreeMap<String, List<Long>>();
  private int maxDownloadsPerAuthority = 0;
  private File statisticsFile = new File("download-stats.csv");
  public void prepareStatistics() {
    if (this.statisticsFile.exists()) {
      long cutOffMillis = System.currentTimeMillis()
          - (7L * 24L * 60L * 60L * 1000L);
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            this.statisticsFile));
        String line;
        while ((line = br.readLine()) != null) {
          String[] parts = line.split(",");
          long requestStartMillis = Long.parseLong(parts[1]);
          if (requestStartMillis < cutOffMillis) {
            continue;
          }
          String authority = parts[0];
          if (!this.downloadData.containsKey(authority)) {
            this.downloadData.put(authority, new ArrayList<Long>());
          }
          long fetchTimeMillis = Long.parseLong(parts[2]);
          this.downloadData.get(authority).add(fetchTimeMillis);
        }
        br.close();
      } catch (IOException e) {
        System.err.println("Could not read "
            + this.statisticsFile.getAbsolutePath() + ".  Ignoring.");
      }
      for (Map.Entry<String, List<Long>> e :
          this.downloadData.entrySet()) {
        Collections.sort(e.getValue());
        int downloads = e.getValue().size();
        if (downloads > this.maxDownloadsPerAuthority) {
          this.maxDownloadsPerAuthority = downloads;
        }
      }
    }
  }
  public SortedSet<String> getKnownAuthorities() {
    return new TreeSet<String>(this.downloadData.keySet());
  }
  public String getPercentile(String authority, int percentile) {
    if (percentile < 0 || percentile > 100 ||
        !this.downloadData.containsKey(authority)) {
      return "NA";
    } else {
      List<Long> fetchTimes = this.downloadData.get(authority);
      int index = (percentile * (fetchTimes.size() - 1)) / 100;
      return String.valueOf(fetchTimes.get(index));
    }
  }
  public String getNAs(String authority) {
    if (!this.downloadData.containsKey(authority)) {
      return "NA";
    } else {
      return String.valueOf(this.maxDownloadsPerAuthority
          - this.downloadData.get(authority).size());
    }
  }
}

