# FityBot for Twitter

FityBot for Twitter is a twitter bot.

## Requirements

  - Python 2.7.x
  - [PycURL](http://pycurl.sourceforge.net/)
  - (optional) [termcolor](https://pypi.python.org/pypi/termcolor).
  This is optional for the `print` plugin.

## Usage

Copy `config-example.py` to `~/.config/fitybot-twitter/config.py`, and
edit it.  You need to at least provide a consumer key pair.  All other
settings are optional.

Run `fitybot.py`. By default it will try to load plugins from
directory `plugins` under the current directory.  If this is the first
time you run it, you will be prompted to copy a PIN from an address.
This is where it requests a access key pair from Twitter.  After that
the key pair is stored in `~/.config/fitybot-twitter/auth.ini`.

Then FityBot will start to listening for any incoming tweets on its
timeline.

## The Plugin System

By itself, `fitybot.py` does not do much.  You will need to populate
its plugin directory with plugins.  Plugins are Python modules with
functions in them.  Before going into the detail, there are two
structures you will use a lot to write a plugin:

  1. A tweet, or a message.  In FityBot, a tweet is a map (dictionary)
  loaded from a JSON.  A description of the structure of the JSON can
  be found
  [here](https://dev.twitter.com/docs/platform-objects/tweets).

  2. `TwitterStream` class.  It contains all the information of a
  connection to Twitter.  You will need it to post tweets or reply to
  a tweet.
  
  To post a tweet, use `TwitterStream.post` method.  This method
  accept one argument, which is the content you want to post (string).
  
  To reply to a tweet, use `TwitterStream.reply` method.  It accepts
  two arguments.  The first one is the content in your reply (string);
  the second is the tweet you are replying to.  Note that the method
  will automatically add the screen name you are replying to before
  your content.
  
  A `TwitterStream` object also has an `OAuth` object in it, which is
  require to make signed requests to Twitter.  You can acquire the
  Twitter screen name associated with FityBot from variable
  `TwitterStream.OAuth.UserID`.

Now back to plugins.  FityBot is interested in three kinds of
functions in a plugin:

### Tweet hooks

Tweet hooks are functions with name `onTweet`.  You can change this
name in `config.py`.  When FityBot receives any tweets on its
timeline, it will call this function in your plugin with a specific
set of arguments.  A tweet hook should accept four arguments:

  1. A `TwitterStream` object.  You can use it to post tweets or reply
  to a tweet.

  2. The screen name (string) that posted the tweet which triggered
  this hook.
  
  3. The content of the tweet (string) which triggered this hook.
  
  4. The tweet (map) that triggered this hook.
  
### Mention hooks

Mentions hooks are functions with name `onMention`.  You can change
this name in `config.py`.  They are like tweet hooks, but only trigger
when FityBot is mentioned in its timeline.  The arguments of a mention
hook is the same as of a tweet hook.

### Commands

A command is represented by a function whose name starts with `cmd`.
You can change this prefix in `config.py`.  The part in the function
name after `cmd` is the name of the command.  A command is triggered
when FityBot receives a tweet whose content starts with `` ` `` (a
backtick) follow by a command name.  The rest of the tweet is treated
as the parameter of the command.  FityBot will then call the function
associated with the command, and feed the function with four
arguments:

  1. A `TwitterStream` object.
  2. The screen name (string) that posted the tweet which triggered
  this hook.
  3. The parameter of the command (string).
  4. The tweet (map) that triggered this command.
  
An example of a command can be found in the `plugins/test.py`.

Note that command names are *case-insensitive*.

## Some Remarks

I couldn’t find any decent OAuth module for Python, so I write my own.

I wanted to use httplib in Python to send all the non-stream requests,
but apparently there are some bug in the Twitter API.  Twitter always
returns a 406 error with no error message for requests sent with
httplib.  So finally I decided to use PycURL to send all requests.
