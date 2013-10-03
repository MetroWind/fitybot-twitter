import os
import subprocess as SubP
import datetime
import json

PluginDir = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                         "data", "stat")
TrackingIDFilename = os.path.join(PluginDir, "tracking-id.txt")
IDStatFilename = os.path.join(PluginDir, "stat-{tid}.txt")
KeyNumTweets = "n_tweets"

if not os.path.exists(PluginDir):
    os.makedirs(PluginDir)

if not os.path.exists(TrackingIDFilename):
    SubP.call(["touch", TrackingIDFilename])
    
def isTracking(tid):
    with open(TrackingIDFilename, 'r') as IDFiles:
        IDs = [line.strip() for line in IDFiles]
    return tid in IDs

def onTweet(twitter, from_id, text, message):
    if not isTracking(from_id):
        return

    Date = datetime.date.today().isoformat()
    StatFilename = IDStatFilename.format(tid=from_id)
    if os.path.exists(StatFilename):
        with open(StatFilename, 'r') as StatFile:
            Stat = json.load(StatFile)
            if not Date in Stat:
                Stat[Date] = {KeyNumTweets: 0}
    else:
        Stat = {Date: {KeyNumTweets: 0}}

    Stat[Date][KeyNumTweets] += 1
    with open(StatFilename, 'w') as StatFile:
        json.dump(Stat, StatFile)

def cmdTrackMyStat(twitter, from_id, args, message):
    if isTracking(from_id):
        twitter.reply("You are already being tracked.", message)
    else:
        with open(TrackingIDFilename, 'a') as IDFile:
            IDFile.write(from_id)
            IDFile.write('\n')
        twitter.reply("Tracking~~", message)
