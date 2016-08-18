# FunYahoo++
A replacement Yahoo prpl (protocol plugin) for Pidgin/libpurple

In 2016 Yahoo decided that they would give next-to-no notice that they were retiring their old protocol in favour of a brand new protocol that doesn't do nearly as much as the old one.  Whilst Microsoft were kind enough to give people a couple of years to plan transitions for MSN, compare that with the 2 months that Yahoo were so generous to provide.

Unfortunately I drew the short straw and ended up writing this plugin in a rush at the last minute in order to scrape something together for unfortunate Yahoo users to use.

This is not a slight change from the old protocol to a new one, instead, it's a completly different protocol with the Yahoo name slapped on it.  Thus there are [several features that the new protocol doesn't have](https://web.archive.org/web/20160730080614/https://help.yahoo.com/kb/yahoo-messenger-for-web/SLN26860.html):
  * Typing notifications
  * Away/Idle statuses
  * Your old buddy list
  * Bold/italic/underline formatting

[Please don't hate me because they're missing.](https://web.archive.org/web/20160417093742/https://yahoo.uservoice.com/forums/320961)

If you're having trouble logging in, try logging into Yahoo Mail.  For some inexplicable reason, the messenger is linked to that.


### How to set up ###
Add a new account to Pidgin.  The dropdown list should have a "Yahoo (2016)" option.
![add account screenshot](https://cloud.githubusercontent.com/assets/1063865/17792148/5a6cc3f2-65f3-11e6-8ec5-420868403038.png)

### How to install on Windows ###
Download [libyahoo-plusplus.dll](http://eion.robbmob.com/libyahoo-plusplus.dll) and place into your `Program Files\Pidgin\plugins` folder.  (If you haven't used the Facebook, Skypeweb or Hangouts plugin before you'll also need to download  [libjson-glib-1.0.dll](https://github.com/EionRobb/skype4pidgin/raw/master/skypeweb/libjson-glib-1.0.dll) and place that into `Program Files\Pidgin` - not the plugins folder.)

### Whats up with the name? ###
Just a fun jab at some of the forks/clones of Pidgin over the years


GPLv3+ licenced 
