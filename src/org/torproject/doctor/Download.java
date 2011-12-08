/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.doctor;

public class Download {

  /* Nickname of the authority from which this download was made. */
  private String authority;
  public String getAuthority() {
    return this.authority;
  }

  /* Request URL. */
  private String url;
  public String getUrl() {
    return this.url;
  }

  /* Unparsed response string. */
  private String responseString;
  public String getResponseString() {
    return this.responseString;
  }

  /* Request start timestamp. */
  private long requestStartMillis;
  public long getRequestStartMillis() {
    return this.requestStartMillis;
  }

  /* Fetch time in millis. */
  private long fetchTime;
  public long getFetchTime() {
    return this.fetchTime;
  }

  public Download(String authority, String url, String responseString,
      long requestStartMillis, long fetchTime) {
    this.authority = authority;
    this.url = url;
    this.responseString = responseString;
    this.requestStartMillis = requestStartMillis;
    this.fetchTime = fetchTime;
  }
}

