/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;
import java.util.zip.*;

/* Download the latest network status consensus and corresponding
 * votes. */
public class Downloader {

  /* List of directory authorities to download consensuses and votes
   * from. */
  private SortedMap<String, String> authorities =
      new TreeMap<String, String>();
  public Downloader() {
    this.authorities.put("gabelmoo", "212.112.245.170");
    this.authorities.put("tor26", "86.59.21.38");
    this.authorities.put("ides", "216.224.124.114:9030");
    this.authorities.put("maatuska", "213.115.239.118:443");
    this.authorities.put("dannenberg", "193.23.244.244");
    this.authorities.put("urras", "208.83.223.34:443");
    this.authorities.put("moria1", "128.31.0.34:9131");
    this.authorities.put("dizum", "194.109.206.212");
  }

  /* Download a new consensus and corresponding votes. */
  public void downloadFromAuthorities() {
    this.downloadConsensus();
    if (!this.downloadedConsensuses.isEmpty()) {
      this.parseConsensusToFindReferencedVotes();
      this.downloadReferencedVotes();
    }
  }

  /* Download the most recent consensus from all authorities. */
  private List<Download> downloadedConsensuses =
      new ArrayList<Download>();
  private void downloadConsensus() {
    Map<String, String> urls = new HashMap<String, String>();
    for (Map.Entry<String, String> e : this.authorities.entrySet()) {
      String nickname = e.getKey();
      String address = e.getValue();
      String resource = "/tor/status-vote/current/consensus.z";
      String fullUrl = "http://" + address + resource;
      urls.put(fullUrl, nickname);
    }
    this.downloadedConsensuses = this.downloadFromAuthority(urls);
    if (this.downloadedConsensuses.isEmpty()) {
      System.err.println("Could not download consensus from any of the "
          + "directory authorities.  Ignoring.");
    }
  }

  /* Downloads a consensus or vote in a separate thread that can be
   * interrupted after a timeout. */
  private static class DownloadRunnable implements Runnable {
    Thread mainThread;
    String nickname;
    String url;
    String response;
    boolean finished = false;
    long requestStart = 0L, requestEnd = 0L;
    public DownloadRunnable(String nickname, String url) {
      this.mainThread = Thread.currentThread();
      this.nickname = nickname;
      this.url = url;
    }
    public void run() {
      this.requestStart = System.currentTimeMillis();
      try {
        URL u = new URL(this.url);
        HttpURLConnection huc = (HttpURLConnection) u.openConnection();
        huc.setRequestMethod("GET");
        huc.connect();
        int responseCode = huc.getResponseCode();
        if (responseCode == 200) {
          BufferedInputStream in = new BufferedInputStream(
              new InflaterInputStream(huc.getInputStream()));
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          int len;
          byte[] data = new byte[1024];
          while (!this.finished &&
              (len = in.read(data, 0, 1024)) >= 0) {
            baos.write(data, 0, len);
          }
          if (this.finished) {
            return;
          }
          in.close();
          byte[] allData = baos.toByteArray();
          this.response = new String(allData);
          this.finished = true;
          this.mainThread.interrupt();
        }
      } catch (IOException e) {
        /* Can't do much except leaving this.response at null. */
      }
      this.finished = true;
      this.requestEnd = System.currentTimeMillis();
    }
    public Download getDownload() {
      Download result = null;
      if (this.response != null) {
        result = new Download(this.nickname, this.url, this.response,
          this.requestStart, this.requestEnd - this.requestStart);
      }
      return result;
    }
  }

  /* Download one or more consensuses or votes from one or more directory
   * authorities using a timeout of 60 seconds. */
  private List<Download> downloadFromAuthority(Map<String, String> urls) {
    Set<DownloadRunnable> downloadRunnables =
        new HashSet<DownloadRunnable>();
    for (Map.Entry<String, String> e : urls.entrySet()) {
      String url = e.getKey();
      String nickname = e.getValue();
      DownloadRunnable downloadRunnable = new DownloadRunnable(nickname,
          url);
      downloadRunnables.add(downloadRunnable);
      new Thread(downloadRunnable).start();
    }
    long started = System.currentTimeMillis(), sleep;
    while ((sleep = started + 60L * 1000L - System.currentTimeMillis())
        > 0L) {
      try {
        Thread.sleep(sleep);
      } catch (InterruptedException e) {
        /* Do nothing. */
      }
      boolean unfinished = false;
      for (DownloadRunnable downloadRunnable : downloadRunnables) {
        if (!downloadRunnable.finished) {
          unfinished = true;
          break;
        }
      }
      if (!unfinished) {
        break;
      }
    }
    List<Download> responses = new ArrayList<Download>();
    for (DownloadRunnable downloadRunnable : downloadRunnables) {
      Download download = downloadRunnable.getDownload();
      if (download != null) {
        responses.add(download);
      }
      downloadRunnable.finished = true;
    }
    return responses;
  }

  /* Date-time formats to parse and format timestamps. */
  private static SimpleDateFormat dateTimeFormat;
  static {
    dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  /* Parse the downloaded consensus to find fingerprints of directory
   * authorities publishing the corresponding votes. */
  private SortedSet<String> fingerprints = new TreeSet<String>();
  private void parseConsensusToFindReferencedVotes() {
    for (Download download : this.downloadedConsensuses) {
      String downloadedConsensus = download.getResponseString();
      try {
        BufferedReader br = new BufferedReader(new StringReader(
            downloadedConsensus));
        String line;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("valid-after ")) {
            try {
              long validAfterMillis = dateTimeFormat.parse(line.substring(
                  "valid-after ".length())).getTime();
              if (validAfterMillis + 60L * 60L * 1000L <
                  System.currentTimeMillis()) {
                /* Consensus is more than 1 hour old.  We won't be able to
                 * download the corresponding votes anymore. */
                break;
              }
            } catch (ParseException e) {
              System.err.println("Could not parse valid-after timestamp "
                  + "in line '" + line + "' of a downloaded consensus.  "
                  + "Not downloading votes.");
              break;
            }
          } else if (line.startsWith("dir-source ")) {
            String[] parts = line.split(" ");
            if (parts.length < 3) {
              System.err.println("Bad dir-source line '" + line
                  + "' in downloaded consensus.  Skipping.");
              continue;
            }
            String nickname = parts[1];
            if (nickname.endsWith("-legacy")) {
              continue;
            }
            String fingerprint = parts[2];
            this.fingerprints.add(fingerprint);
          }
        }
        br.close();
      } catch (IOException e) {
        System.err.println("Could not parse consensus to find referenced "
            + "votes in it.  Skipping.");
      }
    }
  }

  /* Download the votes published by directory authorities listed in the
   * consensus. */
  private List<Download> downloadedVotes = new ArrayList<Download>();
  private void downloadReferencedVotes() {
    for (String fingerprint : this.fingerprints) {
      String downloadedVote = null;
      List<String> authorities = new ArrayList<String>(
          this.authorities.values());
      Collections.shuffle(authorities);
      for (String authority : authorities) {
        if (downloadedVote != null) {
          break;
        }
        String resource = "/tor/status-vote/current/" + fingerprint
            + ".z";
        String fullUrl = "http://" + authority + resource;
        Map<String, String> urls = new HashMap<String, String>();
        urls.put(fullUrl, authority);
        this.downloadedVotes.addAll(this.downloadFromAuthority(urls));
      }
    }
  }

  /* Return the previously downloaded (unparsed) consensus string by
   * authority nickname. */
  public List<Download> getConsensuses() {
    return this.downloadedConsensuses;
  }

  /* Return the previously downloaded (unparsed) vote strings. */
  public List<Download> getVotes() {
    return this.downloadedVotes;
  }
}

