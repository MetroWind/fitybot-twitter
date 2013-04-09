import random
import os.path

PluginDir = os.path.dirname(__file__)
BlahFileName = os.path.join(PluginDir, "blah.txt")

def onMention(twitter, from_id, text, message):
    Text = text
    if text.startswith("@"):
        # Remove the first mention
        Text = text.partition(' ')[2]
    # If I'm mention in a tweet from others
    with open(BlahFileName, 'r') as BlahFile:
        Blahs = [line.strip().decode("utf-8") for line in BlahFile]
                        
    if len(Blahs) == 0: 
        twitter.reply("Huh??", message)
                        
    GoodBlahs = filter(lambda x : x.find(Text) != -1, Blahs)
    if len(GoodBlahs) == 0:
        twitter.reply(random.choice(Blahs), message)
    else:               
        twitter.reply(random.choice(GoodBlahs), message)

def cmdAddblah(twitter, from_id, args, message):
    Blah = unicode(args.strip())
    with open(BlahFileName, 'a') as BlahFile:
        BlahFile.write(Blah.encode("utf-8"))
        BlahFile.write('\n')
