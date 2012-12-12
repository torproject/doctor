#!/usr/bin/env python
# consensusTracker.py -- alerts for changes in the capacity of the tor network
# Released under the GPL v3 (http://www.gnu.org/licenses/gpl.html)

"""
Quick script for periodically checking relay count and bandwidth available on
the tor network. This sends daily reports or alerts when changes breach a given
threshold. Queries are done for each consensus, tracking stats for guards,
middle hops, and exits separately.

This determines if relays are new by checking if the fingerprint's ever been
seen before, which can take quite some time to prepopulate from scratch (on the
order of a month or so). Getting this information from karsten's metrics
project can greatly bootstrap this.

To fetch the consensus on an hourly basis you either need to have DirPort or
FetchDirInfoEarly set in your torrc (the default, client schedule for fetching
the consensus will miss some since each consensus is valid for two hours).
"""

import os
import sys
import time
import tarfile
import getopt
import getpass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email import Encoders

import stem
import stem.connection
import stem.descriptor.networkstatus
import stem.util.str_tools

# enums representing different poritons of the tor network
RELAY_GUARD, RELAY_MIDDLE, RELAY_EXIT = range(1, 4)

# defaut overwrites
DEFAULT_GMAIL_ACCOUNT = None
DEFAULT_TO_ADDRESS = None
DEFAULT_FINGERPRINTS = "./fingerprints"
DEFAULT_NS_OUTPUT = "./newRelays"

# thresholds at which alerts are sent for relay counts
HOURLY_COUNT_THRESHOLD = 20
HOURLY_BW_THRESHOLD = 6553600 # trying 50 Mbit/s

OPT = "g:t:f:n:qh"
OPT_EXPANDED = ["gmail=", "to=", "fingerprints=", "nsOutput=", "quiet", "help"]
HELP_MSG = """Usage consensusTracker.py [OPTION]
Provides alerts for sharp changes in the size and capacity of the tor network.

  -g, --gmail GMAIL_ADDRESS     account used to send email alerts%s
  -t, --to EMAIL_ADDRESS        destination of email alerts%s
  -f, --fingerprints FP_FILE    location with which fingerprints are persisted%s
  -n, --nsOutput NS_OUTPUT_DIR  path to which to save ns entries for new relays%s
  -q, --quiet                   skips summary output from going to stdout
  -h, --help                    presents this help
"""
FP_WRITE_FAIL_MSG = "Unable to access '%s', fingerprints won't be persisted"

EMAIL_HEADER = """<html>
  <head></head>
  <body>
    <p>%s</p>
    <hr />
    <table style="border-collapse:collapse;">
      <tr>
        <td></td>
        <td colspan="3" bgcolor="green"><b>&nbsp;Guards</b></td>
        <td colspan="3" bgcolor="yellow"><b>&nbsp;Middle</b></td>
        <td colspan="3" bgcolor="red"><b>&nbsp;Exits</b></td>
        <td bgcolor="blue"><b>&nbsp;Total</b></td>
      </tr>
      
      <tr>
        <td bgcolor="#444444"><b>&nbsp;Date:</b></td>
        <td bgcolor="green"><b>&nbsp;Count:&nbsp;</b></td>
        <td bgcolor="green"><b>New:&nbsp;</b></td>
        <td bgcolor="green"><b>Bandwidth:&nbsp;</b></td>
        <td bgcolor="yellow"><b>&nbsp;Count:&nbsp;</b></td>
        <td bgcolor="yellow"><b>New:&nbsp;</b></td>
        <td bgcolor="yellow"><b>Bandwidth:&nbsp;</b></td>
        <td bgcolor="red"><b>&nbsp;Count:&nbsp;</b></td>
        <td bgcolor="red"><b>New:&nbsp;</b></td>
        <td bgcolor="red"><b>Bandwidth:&nbsp;</b></td>
        <td bgcolor="blue"><b>&nbsp;Bandwidth:&nbsp;</b></td>
      </tr>
      
"""

EMAIL_CELL = """
      <tr>
        <td bgcolor="#444444"><b>&nbsp;%s</b></td>
        <td bgcolor="#44FF44"><b>&nbsp;%s</b></td>
        <td bgcolor="#44FF44"><b>%s</b></td>
        <td bgcolor="#44FF44"><b>%s</b></td>
        <td bgcolor="#FFFF44"><b>&nbsp;%s</b></td>
        <td bgcolor="#FFFF44"><b>%s</b></td>
        <td bgcolor="#FFFF44"><b>%s</b></td>
        <td bgcolor="#FF4444"><b>&nbsp;%s</b></td>
        <td bgcolor="#FF4444"><b>%s</b></td>
        <td bgcolor="#FF4444"><b>%s</b></td>
        <td bgcolor="#4444FF"><b>&nbsp;%s</b></td>
      </tr>
"""

def sendViaGmail(gmailAccount, gmailPassword, toAddress, subject, msgText, msgHtml, attachment = None):
  """
  Sends an email via gmail, returning if successful or not.
  
  Arguments:
    gmailAccount  - gmail account to be used (ex, "myname@gmail.com")
    gmailPassword - gmail password
    toAddress     - address email should be sent to
    subject       - email subject
    msg           - email body text
    attachment    - path to file being attached
  """
  
  mimeMsg = MIMEMultipart('alternative')
  mimeMsg['Subject'] = subject
  mimeMsg['From'] = gmailAccount
  mimeMsg['To'] = toAddress
  
  if attachment:
    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(attachment, "rb").read())
    Encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attachment))
    mimeMsg.attach(part)
  
  mimeMsg.attach(MIMEText(msgText, 'plain'))
  mimeMsg.attach(MIMEText(msgHtml, 'html'))
  
  # send the message via the gmail SMTP server
  try:
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.starttls()
    server.login(gmailAccount, gmailPassword)
    
    server.sendmail(gmailAccount, [toAddress], mimeMsg.as_string())
    server.quit()
    
    return True
  except smtplib.SMTPAuthenticationError:
    return False

def isExit(controller, fingerprint, default=False):
  """
  Returns if the given permits exit traffic or not. If unable to fetch the
  descriptor then this provides the default.
  
  Arguments:
  fingerprint - relay to be checked
  default - results if the descriptor is unavailable
  """
  
  try:
    return controller.get_server_descriptor(fingerprint).exit_policy.is_exiting_allowed()
  except:
    return default

def getNextConsensus(controller, oldConsensus, sleepTime = 300):
  """
  This blocks until there's a new consensus available, providing it back when
  it is.
  
  Arguments:
    oldConsensus      - last consensus we've fetched
    sleepTime         - time to wait if a new consensus is unavailable
  """
  
  # periodically checks for a new consensus
  while True:
    try:
      newConsensus = stem.descriptor.networkstatus.NetworkStatusDocumentV3(
        controller.get_info("dir/status-vote/current/consensus")
      )
      
      if oldConsensus and oldConsensus.valid_after == newConsensus.valid_after:
        time.sleep(sleepTime) # consensus hasn't changed
      else:
        return newConsensus
    except stem.SocketClosed:
      print "Connection to tor is closed"
      sys.exit()
    except stem.ControllerError:
      print "Failed to fetch current consensus, waiting and trying again"
      time.sleep(sleepTime)

def getSizeLabel(bytes, decimal = 0):
  """
  Converts byte count into label in its most significant units, for instance
  7500 bytes would return "56 Kb/s".
  """
  
  return stem.util.str_tools.get_size_label(bytes, decimal, is_bytes = False) + "/s"

class Sampling:
  """
  Consensus attributes for a given time period we're concerned with for
  generating alerts.
  """
  
  def __init__(self, controller, consensus, newRelays):
    """
    Creates a new sampling.
    
    Arguments:
      consensus  - latest tor consensus
      newRelays  - listing of router status entries with a fingerprint we
                   haven't seen before
    """
    
    self.validAfter = consensus.valid_after
    
    # constructs mappings of relayType -> [router_status_entry list]
    types = (RELAY_GUARD, RELAY_MIDDLE, RELAY_EXIT)
    self.allRelays = dict([(relayType, []) for relayType in types])
    self.newRelays = dict([(relayType, []) for relayType in types])
    
    for uncategorized, categorized in ((consensus.routers, self.allRelays), (newRelays, self.newRelays)):
      for nsEntry in uncategorized:
        relayType = RELAY_MIDDLE
        if isExit(controller, nsEntry.fingerprint): relayType = RELAY_EXIT
        elif "Guard" in nsEntry.flags: relayType = RELAY_GUARD
        categorized[relayType].append(nsEntry)
  
  def getValidAfter(self):
    return self.validAfter.strftime("%Y-%m-%d %H:%M:%S")
  
  def getRelays(self, newOnly=True):
    if newOnly:
      return self.newRelays[RELAY_GUARD] + self.newRelays[RELAY_MIDDLE] + self.newRelays[RELAY_EXIT]
    else:
      return self.allRelays[RELAY_GUARD] + self.allRelays[RELAY_MIDDLE] + self.allRelays[RELAY_EXIT]
  
  def getCount(self, relayType, newOnly=True):
    if newOnly: return len(self.newRelays[relayType])
    else: return len(self.allRelays[relayType])
  
  def getCounts(self, newOnly=True):
    guardCount = self.getCount(RELAY_GUARD, newOnly)
    middleCount = self.getCount(RELAY_MIDDLE, newOnly)
    exitCount = self.getCount(RELAY_EXIT, newOnly)
    return (guardCount, middleCount, exitCount)
  
  def getBandwidth(self, descInfo, relayType, newOnly=True):
    # Tries to use the observed bandwidth rather than measured since the
    # later is just a heuristic (has little bearing on what the relay
    # actually provides.
    totalBandwidth = 0
    
    relaySet = self.newRelays[relayType] if newOnly else self.allRelays[relayType]
    for nsEntry in relaySet:
      # we might not have a desc entry (or if FetchUselessDescriptors is
      # unset), but when it first appears network status bandwidth is equal to
      # the observed too
      if nsEntry.fingerprint in descInfo: totalBandwidth += descInfo[nsEntry.fingerprint][0]
      elif nsEntry.bandwidth: totalBandwidth += nsEntry.bandwidth
    
    return totalBandwidth
  
  def getSummary(self, descInfo):
    """
    Provides a single line summary like:
    2010-07-18 10:00:00 - 941/1732/821 relays (8/12/4 are new, 153 MB added bandwidth)
    """
    
    totalBandwidth = 0
    for relayType in (RELAY_GUARD, RELAY_MIDDLE, RELAY_EXIT):
      totalBandwidth += self.getBandwidth(descInfo, relayType)
    
    relayCounts = "%i/%i/%i relays" % (self.getCounts(False))
    newRelayCounts = "%i/%i/%i are new" % (self.getCounts(True))
    return "%s - %s (%s, %s added bandwidth)" % (self.getValidAfter(), relayCounts, newRelayCounts, getSizeLabel(totalBandwidth))

def monitorConsensus():
  gmailAccount, gmailPassword = DEFAULT_GMAIL_ACCOUNT, ""
  toAddress = DEFAULT_TO_ADDRESS
  seenFingerprintsPath = DEFAULT_FINGERPRINTS
  nsOutputPath = DEFAULT_NS_OUTPUT
  isQuiet = False
  
  # parses user input, noting any issues
  try:
    opts, args = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)
  except getopt.GetoptError, exc:
    print str(exc) + " (for usage provide --help)"
    sys.exit()
  
  for opt, arg in opts:
    if opt in ("-g", "--gmail"): gmailAccount = arg
    elif opt in ("-t", "--to"): toAddress = arg
    elif opt in ("-f", "--fingerprints"): seenFingerprintsPath = arg
    elif opt in ("-n", "--nsOutput"): nsOutputPath = arg
    elif opt in ("-q", "--quiet"): isQuiet = True
    elif opt in ("-h", "--help"):
      # notes default values if they exist
      gmailAcctLabel = " (%s)" % gmailAccount if gmailAccount else ""
      toAddrLabel = " (%s)" % toAddress if toAddress else ""
      seenFpLabel = " (%s)" % seenFingerprintsPath if seenFingerprintsPath else ""
      nsOutputLabel = " (%s)" % nsOutputPath if nsOutputPath else ""
      
      print HELP_MSG % (gmailAcctLabel, toAddrLabel, seenFpLabel, nsOutputLabel)
      sys.exit()
  
  # ns output path is a directory, and later expected to end with a slash
  if nsOutputPath and not nsOutputPath.endswith("/"):
    nsOutputPath += "/"
  
  # fetches gmail password if we're sending email alerts
  isEmailUsed = gmailAccount and toAddress
  if isEmailUsed: gmailPassword = getpass.getpass("GMail Password: ")
  
  if not gmailAccount or not gmailPassword or not toAddress:
    print "Email notifications disabled"
  
  # get a control port connection
  controller = stem.connection.connect_port()
  
  if controller == None:
    print "Unable to connect to control port"
    sys.exit(1)
  
  # prepopulate seenFingerprints with past entries if available
  seenFingerprints = set()
  if seenFingerprintsPath and os.path.exists(seenFingerprintsPath):
    try:
      seenFingerprintsFile = open(seenFingerprintsPath, "r")
      
      for entry in seenFingerprintsFile:
        seenFingerprints.add(entry.upper().strip())
      
      seenFingerprintsFile.close()
    except IOError:
      print "Unable to prepopulate fingerprints from %s" % seenFingerprintsPath
  
  seenFingerprintsFile = None
  if seenFingerprintsPath:
    try: seenFingerprintsFile = open(seenFingerprintsPath, "a")
    except IOError: print FP_WRITE_FAIL_MSG % seenFingerprintsPath
  
  tick = 0 # number of consensuses processed
  samplings = []
  consensus = None # latest consensus we've fetched
  
  # fingerprint => (observedBandwidth, exitPolicy) for all relays
  descInfo = {}
  
  try:
    for desc in controller.get_server_descriptors():
      descInfo[desc.fingerprint] = (desc.observed_bandwidth, desc.exit_policy)
  except stem.SocketClosed:
    print "Connection to tor is closed"
    sys.exit()
  except stem.ControllerError, exc:
    print "Unable to query for server descriptors: %s" % exc
    sys.exit()
  
  while True:
    tick += 1
    
    # fetches the consensus, blocking until a new one's available
    consensus = getNextConsensus(controller, consensus)
    
    # determines which entries are new
    newEntries = []
    for router in consensus.routers:
      # adds entry to descInfo hash
      if not router.fingerprint in descInfo:
        try:
          desc = controller.get_server_descriptor(router.fingerprint)
          descInfo[desc.fingerprint] = (desc.observed_bandwidth, desc.exit_policy)
        except stem.SocketClosed:
          print "Connection to tor is closed"
          sys.exit()
        except stem.ControllerError, exc:
          print "Unable to query for server descriptors: %s" % exc
          sys.exit()
      
      if not router.fingerprint in seenFingerprints:
        newEntries.append(router)
        seenFingerprints.add(router.fingerprint)
        
        # records the seen fingerprint
        if seenFingerprintsFile:
          try:
            seenFingerprintsFile.write(router.fingerprint + "\n")
          except IOError:
            print FP_WRITE_FAIL_MSG % seenFingerprintsPath
            seenFingerprintsFile = None
    
    newSampling = Sampling(controller, consensus, newEntries)
    
    # check if we broke any thresholds (currently just checking hourly exit stats)
    countAlert = newSampling.getCount(RELAY_EXIT, True) > HOURLY_COUNT_THRESHOLD
    bwAlert = newSampling.getBandwidth(descInfo, RELAY_EXIT, True) > HOURLY_BW_THRESHOLD
    
    samplings.insert(0, newSampling)
    if len(samplings) > 192:
      # discards last day's worth of results
      lastDate = samplings[-1].getValidAfter().split(" ")[0]
      
      # usually we'll be removing 24 entries, but could possibly be less
      cropStart = -25
      while samplings[cropStart].getValidAfter().split(" ")[0] != lastDate:
        cropStart += 1
      samplings = samplings[:cropStart]
    
    # writes new ns entries
    if nsOutputPath:
      nsContents = ""
      entryDir = nsOutputPath + newSampling.getValidAfter().split(" ")[0] + "/"
      entryFilename = newSampling.getValidAfter().split(" ")[1] + ".txt"
      
      for label, relayType in (("Exits:", RELAY_EXIT), ("Middle:", RELAY_MIDDLE), ("Guards:", RELAY_GUARD)):
        nsContents += label + "\n"
        nsContents += "-" * 40 + "\n"
        for nsEntry in newSampling.newRelays[relayType]:
          # TODO: the str call of the following produces a deprecation warning, as discussed on:
          # https://trac.torproject.org/projects/tor/ticket/1777
          if nsEntry.fingerprint in descInfo:
            bwLabel = getSizeLabel(descInfo[nsEntry.fingerprint][0], 2)
            exitPolicyLabel = ", ".join([str(policyLine) for policyLine in descInfo[nsEntry.fingerprint][1]])
          else:
            bwLabel = getSizeLabel(nsEntry.bandwidth, 2)
            exitPolicyLabel = "Unknown"
          
          nsContents += "%s (%s:%s)\n" % (nsEntry.fingerprint, nsEntry.address, nsEntry.or_port)
          nsContents += "    nickname: %s\n" % nsEntry.nickname
          nsContents += "    bandwidth: %s\n" % bwLabel
          nsContents += "    flags: %s\n" % ", ".join(nsEntry.flags)
          nsContents += "    exit policy: %s\n\n" % exitPolicyLabel
      
      try:
        # make ns entries directory if it doesn't already exist
        if not os.path.exists(entryDir): os.makedirs(entryDir)
        
        # creates subdirectory for each date, then file named after the time
        nsFile = open(entryDir + entryFilename, "w")
        nsFile.write(nsContents)
        nsFile.close()
      except IOError:
        print "Unable to access '%s', network status summaries won't be persisted" % (entryDir + entryFilename)
        nsOutputPath = None
    
    # prints results to terminal, ex:
    # 7. 2010-07-18 10:00:00 - 941/1732/821 relays (8/12/4 are new, 153 MB / 215 MB / 48 MB added bandwidth)
    if not isQuiet:
      print "%i. %s" % (tick, newSampling.getSummary(descInfo))
      if countAlert: print "  *count threshold broken*"
      if bwAlert: print "  *bandwidth threshold broken*"
    
    # checks if, with this entry, we have all the samplings for the day
    isMidnightEntry = newSampling.getValidAfter().split(" ")[1] == "23:00:00"
    
    if countAlert or bwAlert or isMidnightEntry:
      currentTime = time.strftime("%H:%M", time.localtime(time.time()))
      currentDate = time.strftime("%m/%d/%Y", time.localtime(time.time()))
      
      if countAlert:
        subject = "Alert: Relay Count Threshold Broken"
        noticeBody = "The relay count threshold was broken today at %s (%s) with the addition of %i new exits (the current threshold is set at %i)."
        noticeMsg = noticeBody % (currentTime, currentDate, newSampling.getCount(RELAY_EXIT), HOURLY_COUNT_THRESHOLD)
      elif bwAlert:
        subject = "Alert: Relay Bandwidth Threshold Broken"
        noticeBody = "The relay bandwidth threshold was broken today at %s (%s) with the addition of %s of new exit capacity (the current threshold is set at %s)."
        noticeMsg = noticeBody % (currentTime, currentDate, getSizeLabel(newSampling.getBandwidth(descInfo, RELAY_EXIT)), getSizeLabel(HOURLY_BW_THRESHOLD))
      else:
        subject = "Daily Consensus Report for %s" % currentDate
        noticeMsg = "At present there's no breaches to report. See below for a summary of consensus additions."
      
      greetingMsg = "Greetings from your friendly consensus monitoring daemon. %s" % noticeMsg
      
      # constructs the plain text message
      msgText = greetingMsg + "\n"
      msgText += "-" * 80 + "\n\n"
      
      for sampling in samplings:
        msgText += sampling.getSummary(descInfo) + "\n"
      
      # constructs the html message
      
      msgHtml = EMAIL_HEADER % greetingMsg
      hourlyCellEntry = EMAIL_CELL.replace("<b>", "").replace("</b>", "").replace("44", "88")
      
      # make a mapping of date => [samplings]
      datesToSamplings = {}
      
      for sampling in samplings:
        consensusDate = sampling.getValidAfter().split(" ")[0]
        
        if consensusDate in datesToSamplings:
          datesToSamplings[consensusDate].append(sampling)
        else:
          datesToSamplings[consensusDate] = [sampling]
      
      dates = list(datesToSamplings.keys())
      dates.sort()
      dates.reverse()
      
      for date in dates:
        # stores to get the daily sums later
        gCounts, gNew, gBw = [], [], []
        mCounts, mNew, mBw = [], [], []
        eCounts, eNew, eBw = [], [], []
        
        # prepopulates bandwidth data since we're using diffs
        totalBw = []
        
        for sampling in datesToSamplings[date]:
          samplingTotalBw = 0
          for nsEntry in sampling.getRelays(False):
            if nsEntry.fingerprint in descInfo:
              samplingTotalBw += descInfo[nsEntry.fingerprint][0]
            else:
              samplingTotalBw += nsEntry.bandwidth
          totalBw.append(samplingTotalBw)
        
        hourlyEntries = ""
        for i in range(len(datesToSamplings[date])):
          sampling = datesToSamplings[date][i]
          
          if i == len(datesToSamplings[date]) - 1:
            bwLabel = "" # this is the last entry (no diff)
          else:
            bwLabel = getSizeLabel(totalBw[i] - totalBw[i + 1])
            
            # appends plus symbol if positive
            if bwLabel[0] != "-": bwLabel = "+" + bwLabel
          
          consensusTime = sampling.getValidAfter().split(" ")[1]
          
          gCounts.append(sampling.getCount(RELAY_GUARD, False))
          gNew.append(sampling.getCount(RELAY_GUARD))
          gBw.append(sampling.getBandwidth(descInfo, RELAY_GUARD))
          
          mCounts.append(sampling.getCount(RELAY_MIDDLE, False))
          mNew.append(sampling.getCount(RELAY_MIDDLE))
          mBw.append(sampling.getBandwidth(descInfo, RELAY_MIDDLE))
          
          eCounts.append(sampling.getCount(RELAY_EXIT, False))
          eNew.append(sampling.getCount(RELAY_EXIT))
          eBw.append(sampling.getBandwidth(descInfo, RELAY_EXIT))
          
          hourlyEntries += hourlyCellEntry % (consensusTime, gCounts[-1], gNew[-1], getSizeLabel(gBw[-1]), mCounts[-1], mNew[-1], getSizeLabel(mBw[-1]), eCounts[-1], eNew[-1], getSizeLabel(eBw[-1]), bwLabel)
        
        # append daily summary then hourly entries
        gCountAvg = sum(gCounts) / len(gCounts)
        mCountAvg = sum(mCounts) / len(mCounts)
        eCountAvg = sum(eCounts) / len(eCounts)
        
        bwAvgLabel = getSizeLabel(sum(totalBw) / len(totalBw), 2)
        msgHtml += EMAIL_CELL % (date + "&nbsp;", gCountAvg, sum(gNew), getSizeLabel(sum(gBw)), mCountAvg, sum(mNew), getSizeLabel(sum(mBw)), eCountAvg, sum(eNew), getSizeLabel(sum(eBw)), bwAvgLabel)
        msgHtml += hourlyEntries
      
      msgHtml += """    </table>
  </body>
</html>"""
      
      # creates a tarball with the ns entries directory
      attachment = None
      if nsOutputPath:
        try:
          t = tarfile.open(nsOutputPath[:-1] + ".tar.gz", mode = 'w:gz')
          t.add(nsOutputPath)
          t.close()
          attachment = nsOutputPath[:-1] + ".tar.gz"
        except IOError:
          print "Unable to email archive with new relays."
      
      if gmailAccount and gmailPassword and toAddress:
        sendViaGmail(gmailAccount, gmailPassword, toAddress, subject, msgText, msgHtml, attachment)

if __name__ == '__main__':
  monitorConsensus()

