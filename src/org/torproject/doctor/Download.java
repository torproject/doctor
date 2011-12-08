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

  /* Fetch time in millis. */
  private long fetchTime;
  public long getFetchTime() {
    return this.fetchTime;
  }

  public Download(String authority, String url, String responseString,
      long fetchTime) {
    this.authority = authority;
    this.responseString = responseString;
    this.fetchTime = fetchTime;
  }
}

