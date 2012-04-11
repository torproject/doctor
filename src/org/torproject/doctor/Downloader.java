/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.util.*;
import org.torproject.descriptor.*;

/* Download the latest network status consensus and corresponding
 * votes using metrics-lib. */
public class Downloader {

  /* Download the current consensus and corresponding votes. */
  public List<DescriptorRequest> downloadFromAuthorities() {

    /* Create a descriptor downloader instance that will do all the hard
     * download work for us. */
    DescriptorDownloader downloader =
        DescriptorSourceFactory.createDescriptorDownloader();

    /* Configure the currently known directory authorities. */
    downloader.addDirectoryAuthority("gabelmoo", "212.112.245.170", 80);
    downloader.addDirectoryAuthority("tor26", "86.59.21.38", 80);
    downloader.addDirectoryAuthority("turtles", "76.73.17.194", 9030);
    downloader.addDirectoryAuthority("maatuska", "171.25.193.9", 443);
    downloader.addDirectoryAuthority("dannenberg", "193.23.244.244", 80);
    downloader.addDirectoryAuthority("urras", "208.83.223.34", 443);
    downloader.addDirectoryAuthority("moria1", "128.31.0.34", 9131);
    downloader.addDirectoryAuthority("dizum", "194.109.206.212", 80);

    /* Instruct the downloader to include the current consensus and all
     * referenced votes in the downloads.  The consensus shall be
     * downloaded from all directory authorities, not just from one. */
    downloader.setIncludeCurrentConsensusFromAllDirectoryAuthorities();
    downloader.setIncludeCurrentReferencedVotes();

    /* Iterate over the finished (or aborted) requests and memorize the
     * included consensuses or votes.  The processing will take place
     * later. */
    Iterator<DescriptorRequest> descriptorRequests =
        downloader.downloadDescriptors();
    List<DescriptorRequest> allRequests =
        new ArrayList<DescriptorRequest>();
    while (descriptorRequests.hasNext()) {
      try {
        allRequests.add(descriptorRequests.next());
      } catch (NoSuchElementException e) {
        /* TODO In theory, this exception shouldn't be thrown.  This is a
         * bug in metrics-lib. */
        System.err.println("Internal error: next() doesn't provide an "
            + "element even though hasNext() returned true.  Got "
            + allRequests.size() + " elements so far.  Stopping to "
            + "request further elements.");
        break;
      }
    }

    /* We downloaded everything we wanted. */
    return allRequests;
  }
}

