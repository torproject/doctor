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

  /* Download a new consensus and corresponding votes. */
  public void downloadFromAuthorities() {

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

    Iterator<DescriptorRequest> descriptorRequests =
        downloader.downloadDescriptors();
    while (descriptorRequests.hasNext()) {
      DescriptorRequest request = descriptorRequests.next();
      String authority = request.getDirectoryNickname();
      String requestUrl = request.getRequestUrl();
      long requestStart = request.getRequestStart();
      long fetchTime = request.getRequestEnd()
          - request.getRequestStart();
      if (request.globalTimeoutHasExpired()) {
        System.err.println("Global timeout has expired.  Exiting.");
        System.exit(1);
      } else if (!request.requestTimeoutHasExpired()) {
        if (request.getDescriptors().isEmpty()) {
          /* No response.  We'll realize later on if we're missing a
           * consensus or vote. */
          continue;
        } else if (request.getDescriptors().size() > 1) {
          System.out.println("Response contains more than 1 "
              + "descriptor.  Considering only the first.");
        }
        Descriptor downloadedDescriptor = request.getDescriptors().get(0);
        String response = new String(request.getDescriptors().get(0).
            getRawDescriptorBytes());
        Download download = new Download(authority, requestUrl, response,
            requestStart, fetchTime);
        if (downloadedDescriptor instanceof
            RelayNetworkStatusConsensus) {
          this.downloadedConsensuses.add(download);
        } else if (downloadedDescriptor instanceof
            RelayNetworkStatusVote) {
          this.downloadedVotes.add(download);
        } else {
          System.err.println("Did not expect a descriptor of type "
              + downloadedDescriptor.getClass() + ".  Ignoring.");
        }
      }
    }
  }

  /* Return the previously downloaded (unparsed) consensus string by
   * authority nickname. */
  private List<Download> downloadedConsensuses =
      new ArrayList<Download>();
  public List<Download> getConsensuses() {
    return this.downloadedConsensuses;
  }

  /* Return the previously downloaded (unparsed) vote strings. */
  private List<Download> downloadedVotes = new ArrayList<Download>();
  public List<Download> getVotes() {
    return this.downloadedVotes;
  }
}

