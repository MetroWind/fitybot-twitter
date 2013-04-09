try:
    from termcolor import colored
except ImportError:
    def colored(text, color, **kwargs):
        return text

def onTweet(twitter, from_id, text, message):
    print 'Got tweet from @{0}:'.format(colored(from_id, 'green'))
    print "  " + text
