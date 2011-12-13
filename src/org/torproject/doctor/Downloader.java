/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;
import java.util.zip.*;
import org.torproject.descriptor.*;

/* Download the latest network status consensus and corresponding
 * votes. */
public class Downloader {

  /* Download the current consensus and corresponding votes. */
  public List<DescriptorRequest> downloadFromAuthorities() {

    RelayDescriptorDownloader downloader =
        DescriptorSourceFactory.createRelayDescriptorDownloader();

    downloader.addDirectoryAuthority("gabelmoo", "212.112.245.170", 80);
    downloader.addDirectoryAuthority("tor26", "86.59.21.38", 80);
    downloader.addDirectoryAuthority("ides", "216.224.124.114", 9030);
    downloader.addDirectoryAuthority("maatuska", "213.115.239.118", 443);
    downloader.addDirectoryAuthority("dannenberg", "193.23.244.244", 80);
    downloader.addDirectoryAuthority("urras", "208.83.223.34", 443);
    downloader.addDirectoryAuthority("moria1", "128.31.0.34", 9131);
    downloader.addDirectoryAuthority("dizum", "194.109.206.212", 80);

    downloader.setIncludeCurrentConsensusFromAllDirectoryAuthorities();
    downloader.setIncludeCurrentReferencedVotes();

    downloader.setRequestTimeout(60L * 1000L);

    List<DescriptorRequest> allRequests =
        new ArrayList<DescriptorRequest>();
    Iterator<DescriptorRequest> descriptorRequests =
        downloader.downloadDescriptors();
    while (descriptorRequests.hasNext()) {
      try {
        allRequests.add(descriptorRequests.next());
      } catch (NoSuchElementException e) {
        /* TODO In theory, this exception shouldn't be thrown. */
        System.err.println("Internal error: next() doesn't provide an "
            + "element even though hasNext() returned true.  Got "
            + allRequests.size() + " elements so far.  Stopping to "
            + "request further elements.");
        break;
      }
    }

    return allRequests;
  }
}

