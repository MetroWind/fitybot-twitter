#!/usr/bin/env python
# For Python 2

import sys, os
import StringIO
import re
import time
import pycurl
import urllib
import urlparse
import json
import random
random.seed()
import hashlib
import hmac
import base64
import logging
import pprint
import ConfigParser
import imp

Logger = logging.getLogger("Main")
Logger.setLevel(logging.INFO)
Logger.addHandler(logging.StreamHandler(sys.stderr))
PP = pprint.PrettyPrinter(indent=2)

class Defaults:
    UserAgent = 'FityBot'
    PluginDir = "plugins"
    CmdPrefix = '`'
    MentionHookName = "onMention"
    TweetHookName = "onTweet"
    CmdFuncPrefix = "cmd"

CONFIG_NAME = "fitybot-twitter"
CONF_AUTH_NAME = "auth.ini"
CONF_NAME = "config.py"

def dictUnicodeToStr(src, codec="utf-8"):
    """Convert any unicode values in dictionary `src' into strings.
    """
    Rtn = {}
    for key in src:
        if isinstance(src[key], unicode):
            Rtn[key] = src[key].encode(codec)
        else:
            Rtn[key] = src[key]
    return Rtn

def ampSepStrToDict(amp_set_str, unquote=False):
    """Parse %-encoded key-value pairs like you would see in URLs into
    a dictionary.  If `unquote' is true, also %-decode.
    """
    D = {}
    for Pair in amp_set_str.split('&'):
        Key, Value = Pair.split('=')
        if unquote:
            D[urllib.unquote(Key)] = urllib.unquote(Value)
        else:
            D[Key] = Value
    return D

class OAuth(object):
    """A class for OAuth.  Terminology:

    OAuth parameters: The parameters in the Authorization http header
    for a signed message.  Also additional OAuth parameters means any
    OAuth parameters other than the 7 described in
    https://dev.twitter.com/docs/auth/authorizing-request.

    URL parameters: The parameters in the URL after the '?'.

    Body parameters: The parameters in the body of a http request,
    also %-encoded.
    """
    def __init__(self, consumer_key="", consumer_secret=""):
        self.ConsumerKey = consumer_key
        self.ConsumerSecret = consumer_secret
        self.Token = ""
        self.TokenSecret = ""
        self.URLParams = {}
        self.BodyParams = {}
        self.UserID = ""
        self.UserAgent = ""
        # self.OAuthParams = {}

    def genSigBaseStr(self, method, base_url, oauth_params, url_params={}, body_params={}):
        """Generate the signature base string for signing.
        """
        AllParams = {}
        AllParams.update(url_params)
        AllParams.update(oauth_params)
        AllParams.update(body_params)
        Logger.debug("AllParams:")
        Logger.debug(PP.pformat(AllParams))
        ParamStr = '&'.join(['='.join([urllib.quote(key, ''),
                                       urllib.quote(AllParams[key], '')]) \
                             for key in sorted(AllParams.keys())])
        Str = '&'.join([method.upper(), urllib.quote(base_url, ''),
                        urllib.quote(ParamStr, '')])
        return Str

    def genNonce(self):
        """Generate the oauth_nonce string.
        """
        random_number = ''.join(str(random.randint(0, 9)) for i in range(40))
        m = hashlib.md5()
        m.update(str(time.time()) + str(random_number))
        return m.hexdigest()

    def genTimestamp(self):
        """Generate the oauth_timestamp string.
        """
        return str(int(time.time()))

    def request(self, method, domain, url, addtional_oauth_params={},
                url_params={}, body_params={}):
        """Issue a HTTP request.  `url' is the part after the domain name.
        """
        # NOTE: There's a bug in Twitter API, if we use httplib to
        # call statues/update, we'll always get 406 error without any
        # error message.  So we have to use pycurl.

        # Decode any unicode to string to prevent any hassels later
        # on.  Python 2 sucks...
        AddOAuthParams = dictUnicodeToStr(addtional_oauth_params)
        URLParams = dictUnicodeToStr(url_params)
        BodyParams = dictUnicodeToStr(body_params)

        BaseURL = urlparse.urlunsplit(("https", domain, url, "", ""))
        OAuthHeader = self.sign(method, BaseURL, AddOAuthParams, URLParams, BodyParams)
        URL = BaseURL
        if URLParams:
            # Add any url parameters to the base url if needed.
            URL = '&'.join([BaseURL, urllib.urlencode(URLParams)])
        Header = ["Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
                  "Host: " + domain,
                  "Authorization: " + OAuthHeader]

        # Body of the responce will go here
        AuthResp = StringIO.StringIO()
        # Header of the responce will go here
        RespHeader = StringIO.StringIO()

        AuthConn = pycurl.Curl()
        AuthConn.setopt(pycurl.URL, URL)
        AuthConn.setopt(pycurl.VERBOSE, 0)
        AuthConn.setopt(pycurl.USERAGENT, self.UserAgent)
        AuthConn.setopt(pycurl.ENCODING, 'deflate, gzip')
        if method.upper() == "POST":
            AuthConn.setopt(pycurl.POST, 1)
            # Post the body parameters
            AuthConn.setopt(pycurl.POSTFIELDS, urllib.urlencode(BodyParams))
        AuthConn.setopt(pycurl.HTTPHEADER, Header)
        AuthConn.setopt(pycurl.WRITEFUNCTION, AuthResp.write)
        AuthConn.setopt(pycurl.HEADERFUNCTION, RespHeader.write)
        AuthConn.perform()

        # Body of the responce as a string
        Body = AuthResp.getvalue()
        Logger.debug("<--- " + Body)
        if AuthConn.getinfo(pycurl.HTTP_CODE) != 200:
            # The server didn't like our message, or there was some
            # network issues.

            # Getting the reason message from the header...
            RespStatus = RespHeader.getvalue().splitlines()[0]
            HttpMsg = ""
            M = re.match(r'HTTP\/\S*\s*\d+\s*(.*?)\s*$', RespStatus)
            if M:
                HttpMsg = M.groups(1)
            raise RuntimeError("{0} {1}\n{2}".format(AuthConn.getinfo(pycurl.HTTP_CODE),
                                                  HttpMsg, Body))
        return Body

    def sign(self, method, base_url, addtional_oauth_params={}, url_params={}, body_params={}):
        if not self.ConsumerKey:
            Logger.critical("Cannot sign request, need consumer key.")
            sys.exit(1)

        # These 5 oauth parameters and the signature are there no
        # matter whether we have the access key or not.
        OAuthParams = {"oauth_nonce": self.genNonce(),
                       "oauth_signature_method": "HMAC-SHA1",
                       "oauth_timestamp": self.genTimestamp(),
                       "oauth_consumer_key": self.ConsumerKey,
                       "oauth_version": "1.0"}
        if self.Token:
            # We already have the access key.
            OAuthParams["oauth_token"] = self.Token
        OAuthParams.update(addtional_oauth_params)

        # Build the hash key from the consumer secret...
        HashKey = self.ConsumerSecret + '&'
        if self.TokenSecret:
            # ... and the token secret.
            HashKey += self.TokenSecret
        Logger.debug("Signing with hashkey {0}...".format(HashKey))
        SigBaseStr = self.genSigBaseStr(method, base_url, OAuthParams, url_params, body_params)
        Logger.debug("Signature base string: " + SigBaseStr)
        # Hash the base string!
        m = hmac.new(HashKey, SigBaseStr, hashlib.sha1)
        OAuthSig = base64.b64encode(m.digest())

        OAuthParamsWithSig = {}
        OAuthParamsWithSig.update(OAuthParams)
        OAuthParamsWithSig["oauth_signature"] = OAuthSig
        # Now 7 OAuth parameters are all ready (or 6 if we don't have
        # the access key).

        OAuthStr = ", ".join([''.join([urllib.quote(key, ''), '="',
                                       urllib.quote(OAuthParamsWithSig[key], ''), '"']) \
                              for key in sorted(OAuthParamsWithSig.keys())])
        HeaderStr = "OAuth " + OAuthStr
        Logger.debug("Signed OAuth header str: " + HeaderStr)
        return HeaderStr

    def accessToken(self, req_token, req_verifier):
        Data = self.request("POST", "api.twitter.com", "/oauth/access_token", {"oauth_token": req_token},
                            body_params={"oauth_verifier": req_verifier})
        Token = ampSepStrToDict(Data)
        if not "oauth_token_secret" in Token:
            raise RuntimeError("Failed to acquire access token.")
        Logger.debug("Got access token:")
        Logger.debug(PP.pformat(Token))
        # We successfully got the access key.
        self.Token = Token["oauth_token"]
        self.TokenSecret = Token["oauth_token_secret"]
        self.UserID = Token["screen_name"]
        return self.UserID

    def requestToken(self, callback_url="oob"):
        """Get a request token from twitter, then returns (request_token, request_verifier).
        """
        Token = ampSepStrToDict(self.request("POST", "api.twitter.com", "/oauth/request_token",
                                             {"oauth_callback": callback_url}))
        if not Token["oauth_callback_confirmed"] == "true":
            raise RuntimeError("Failed to acquire request token.")

        Logger.debug("Got request token {0}.".format(Token["oauth_token"]))
        Logger.debug("Got token secret {0}.".format(Token["oauth_token_secret"]))
        Pin = None
        if callback_url == "oob":
            print "Get PIN from here:"
            print
            print "  https://api.twitter.com/oauth/authorize?oauth_token=" + Token["oauth_token"]
            print
            Pin = raw_input("Then input the PIN here: ")
        return (Token["oauth_token"], Pin)

    def signInWithPIN(self):
        Token = self.requestToken()
        self.accessToken(*Token)

class TwitterConfig(object):
    def __init__(self):
        pass

class TwitterStream(object):
    def __init__(self, config):
        self.Buffer = ''
        self.Connection = None
        self.Config = config
        self.Auth = OAuth(config.ConsumerKey, config.ConsumerSecret)
        self.Auth.UserAgent = config.UserAgent
        self.BaseURL = ""
        self.Method = "GET"
        self.URLParams = {}

        self.MentionHooks = []
        self.TweetHooks = []
        self.Commands = {}

        self.ShouldClose = False

    def setupConnection(self):
        """ Create persistant HTTP connection to Streaming API endpoint using cURL.
        """
        if self.Connection:
            self.Connection.close()
            self.Buffer = ''
        self.Connection = pycurl.Curl()
        self.Connection.setopt(pycurl.VERBOSE, 0)
        self.Connection.setopt(pycurl.URL, self.BaseURL)
        self.Connection.setopt(pycurl.USERAGENT, self.Config.UserAgent)
        # Using gzip is optional but saves us bandwidth.
        self.Connection.setopt(pycurl.ENCODING, 'deflate, gzip')
        if self.Method.upper() == "POST":
            self.Connection.setopt(pycurl.POST, 1)
            self.Connection.setopt(pycurl.POSTFIELDS, urllib.urlencode(self.URLParams))
        elif self.Method.upper() == "GET":
            if self.URLParams:
                self.Connection.setopt(pycurl.URL, '?'.join([self.BaseURL, urllib.urlencode(self.URLParams)]))

        HeaderStr = self.Auth.sign(self.Method, self.BaseURL, url_params=self.URLParams)
        Host = urlparse.urlparse(self.BaseURL).netloc
        self.Connection.setopt(pycurl.HTTPHEADER, ["Host: " + Host,
                                                   "Authorization: " + HeaderStr])
        # self.handle_tweet is the method that are called when new tweets arrive
        self.Connection.setopt(pycurl.WRITEFUNCTION, self.onTweet)

    def signIn(self):
        self.Auth.signInWithPIN()

    def start(self):
        """ Start listening to Streaming endpoint.
        Handle exceptions according to Twitter's recommendations.
        """
        BackoffNetworkError = 0.25
        BackoffHttpError = 5
        BackoffRateLimit = 60
        while not self.ShouldClose:
            self.setupConnection()
            Logger.info("Listening for tweets...")
            try:
                self.Connection.perform()
            except:
                # Network error, use linear back off up to 16 seconds
                print 'Network error: %s' % self.Connection.errstr()
                print 'Waiting %s seconds before trying again' % BackoffNetworkError
                time.sleep(BackoffNetworkError)
                BackoffNetworkError = min(BackoffNetworkError + 1, 16)
                continue
            # HTTP Error
            sc = self.Connection.getinfo(pycurl.HTTP_CODE)
            if sc == 420:
                # Rate limit, use exponential back off starting with 1 minute and double each attempt
                print 'Rate limit, waiting %s seconds' % BackoffRateLimit
                time.sleep(BackoffRateLimit)
                BackoffRateLimit *= 2
            else:
                # HTTP error, use exponential back off up to 320 seconds
                print 'HTTP error %s, %s' % (sc, self.Connection.errstr())
                print 'Waiting %s seconds' % BackoffHttpError
                time.sleep(BackoffHttpError)
                BackoffHttpError = min(BackoffHttpError * 2, 320)

    def reply(self, msg, in_reply_to):
        """`msg' should not contain the @userid at beginning.
        `in_reply_to' is the message dictionary that is being replyed.
        """
        FromID = in_reply_to["user"]["screen_name"]
        self.Auth.request("POST", "api.twitter.com", "/1.1/statuses/update.json",
                          body_params={"in_reply_to_status_id": str(in_reply_to["id"]),
                                      "status": u"@{0} {1}".format(FromID, msg)})
    def post(self, msg):
        self.Auth.request("POST", "api.twitter.com", "/1.1/statuses/update.json",
                          body_params={"status": msg})
    def isMe(self, name):
        """See if screen name `name' is me.
        """
        return name.lower() == self.Auth.UserID.lower()

    def isMentionedIn(self, msg_dict):
        for User in msg_dict["entities"]["user_mentions"]:
            if self.isMe(User["screen_name"]):
                return True
        return False

    def onTweet(self, data):
        """ This method is called when data is received through Streaming endpoint.
        """
        if self.ShouldClose:
            return -1

        self.Buffer += data
        if data.endswith('\r\n') and self.Buffer.strip():
            # complete message received
            Message = json.loads(self.Buffer)
            self.Buffer = ''
            msg = ''
            if Message.get('limit'):
                Logger.info('Rate limiting caused us to miss %s tweets' % (Message['limit'].get('track')))
            elif Message.get('disconnect'):
                raise Exception('Got disconnect: %s' % Message['disconnect'].get('reason'))
            elif Message.get('warning'):
                Logger.warn('Got warning: %s' % Message['warning'].get('message'))
            elif "id" in Message:
                # Got a tweet.
                From = Message["user"]["screen_name"]
                Text = Message.get('text')
                # Run tweet hooks
                for Hook in self.TweetHooks:
                    Hook(self, From, Text, Message)

                if (not self.isMe(From)) and self.isMentionedIn(Message):
                    # I'm mentioned in the tweet, and the tweet is not
                    # from myself.

                    if Text.lower().startswith("@" + self.Auth.UserID.lower()):
                        # Tweet starts with my id, remove that part.
                        MainText = Text.partition(' ')[2]
                        if MainText.startswith(self.Config.CmdPrefix):
                            # This tweet is a command
                            Command, _, Args = MainText[len(self.Config.CmdPrefix):
                                                        ].partition(' ')
                            if Command in self.Commands:
                                Logger.info(u"{0} issued command {1} with argument '{2}'."
                                            .format(From, Command, Args))
                                self.Commands[Command](self, From, Args, Message)
                            else:
                                self.reply(u"Command not found: {0}.".format(Command),
                                           Message)
                            return

                    # Run mention hooks
                    for Hook in self.MentionHooks:
                        Hook(self, From, Text, Message)
                    return

def loadConfig():
    # Look ~/.config/fitybot-twitter for config
    HomeDir = os.environ['HOME']
    ConfDir = os.path.join(HomeDir, ".config", CONFIG_NAME)
    ConfFileNameAuth = os.path.join(ConfDir, CONF_AUTH_NAME)
    ConfFileName = os.path.join(ConfDir, CONF_NAME)

    if not os.path.exists(ConfFileName):
        Logger.critical("Could not find configuration {0}.  "
                     "I need it to have the consumer key pair.  "
                     "Exiting...".format(ConfFileName))
        sys.exit(1)
    ModuleInfo = imp.find_module("config", [ConfDir,])
    Conf = imp.load_module("config", *ModuleInfo)
    Config = TwitterConfig()
    Config.ConfFileNameAuth = ConfFileNameAuth
    Config.UserAgent = getattr(Conf, "UserAgent", Defaults.UserAgent)
    Config.CmdPrefix = getattr(Conf, "CommandPrefix", Defaults.CmdPrefix)
    Config.PluginDir = getattr(Conf, "PluginDir", Defaults.PluginDir)
    Config.MentionHookName = getattr(Conf, "MentionHookName", Defaults.MentionHookName)
    Config.TweetHookName = getattr(Conf, "TweetHookName", Defaults.TweetHookName)
    Config.CmdFuncPrefix = getattr(Conf, "CmdFuncPrefix", Defaults.CmdFuncPrefix)
    try:
        Config.ConsumerKey = Conf.ConsumerKey
        Config.ConsumerSecret = Conf.ConsumerSecret
    except AttributeError:
        Logger.critical("Could not find consumer key pair in your configuration.  "
                        "Existing...")
        sys.exit(1)

    return Config

def loadPlugins(config):
    # Load plugins
    PluginDir = config.PluginDir
    import glob
    # Find all .py files in the plugin dir.
    PluginFiles = glob.glob(os.path.join(PluginDir, "*.py"))
    # Filter out the files with name starting with '_'.
    PluginFiles = [f for f in PluginFiles if not f.startswith('_')]
    Logger.debug("Found plugin files:")
    Logger.debug(PP.pformat(PluginFiles))

    MentionHooks = []                   # A list of functions
    TweetHooks = []                     # A list of functions
    Cmds = {}                           # A map cmd -> function
    for PluginFile in PluginFiles:
        BaseName = os.path.splitext(os.path.basename(PluginFile))[0]
        Logger.info("Loading plugin {0}...".format(BaseName))
        ModInfo = imp.find_module(BaseName, [PluginDir,])
        Plugin = imp.load_module(BaseName, *ModInfo)
        Functions = dir(Plugin)
        # Load mention hooks
        if hasattr(Plugin, config.MentionHookName):
            # Found a mention hook
            Logger.info("  Found mention hook.")
            MentionHooks.append(getattr(Plugin, config.MentionHookName))
        # Load tweet hooks
        if hasattr(Plugin, config.TweetHookName):
            # Found a mention hook
            Logger.info("  Found tweet hook.")
            TweetHooks.append(getattr(Plugin, config.TweetHookName))
        # Load commands
        for Func in Functions:
            if Func.startswith(config.CmdFuncPrefix):
                # Found a command.  We don't care the case of the
                # command name.
                Command = Func[len(config.CmdFuncPrefix):].lower()
                Logger.info("  Found command {0}.".format(Command))
                Cmds[Command] = getattr(Plugin, Func)

    return (TweetHooks, MentionHooks, Cmds)

def initialize(config, tweet_hooks, mention_hooks, cmds):
    Config = config
    TweetHooks = tweet_hooks
    MentionHooks = mention_hooks
    Cmds = cmds

    # Now we are ready to construct the twitter stream.
    Twitter = TwitterStream(Config)
    Twitter.MentionHooks = MentionHooks
    Twitter.TweetHooks = TweetHooks
    Twitter.Commands = Cmds

    # Load authentication info from user file
    ConfAuth = ConfigParser.SafeConfigParser()
    if os.path.isfile(Config.ConfFileNameAuth):
        Logger.debug("Auth config file {0} exists, reading...".format(Config.ConfFileNameAuth))
        ConfAuth.read([Config.ConfFileNameAuth,])
        Twitter.Auth.Token = ConfAuth.get("Auth", "Token")
        Twitter.Auth.TokenSecret = ConfAuth.get("Auth", "TokenSecret")
        Twitter.Auth.UserID = ConfAuth.get("Auth", "UserID")
    else:
        Logger.debug("Auth config file {0} deos not exsit.".format(Config.ConfFileNameAuth))
        Logger.info("You don't have an access token pair.  Getting a new one...")
        Twitter.signIn()
        ConfAuth.add_section("Auth")
        ConfAuth.set("Auth", "Token", Twitter.Auth.Token)
        ConfAuth.set("Auth", "TokenSecret", Twitter.Auth.TokenSecret)
        ConfAuth.set("Auth", "UserID", Twitter.Auth.UserID)
        ConfFileAuth = open(Config.ConfFileNameAuth, 'w')
        ConfAuth.write(ConfFileAuth)
        ConfFileAuth.close()
        os.chmod(Config.ConfFileNameAuth, 0600)

    Twitter.BaseURL = "https://userstream.twitter.com/1.1/user.json"
    Twitter.Method = "GET"
    return Twitter

def main(argv):
    Config = loadConfig()

    TweetHooks, MentionHooks, Cmds = loadPlugins(Config)

    Twitter = initialize(Config, TweetHooks, MentionHooks, Cmds)

    import threading
    TwitterThread = threading.Thread(target=Twitter.start, name="Twitter-Worker")
    TwitterThread.daemon = True
    TwitterThread.start()

    def shouldQuit(sig, frame):
        Logger.info("Waiting for connection to close...")
        Twitter.ShouldClose = True
        time.sleep(1)
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, shouldQuit)

    while True:
        time.sleep(10)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
