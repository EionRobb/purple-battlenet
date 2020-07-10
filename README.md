# Battle.net Plugin for libpurple #

A work-in-progress plugin to login and send whispers to Battle.net v2 (a.k.a. Blizzard App) users.

This plugin is written by [Eion Robb](https://eion.robbmob.com/blog/) using protobufs from [the python-bnet repo](https://github.com/HearthSim/python-bnet).  GPLv3+ licensed.

## Login Tips ##
When you login from Pidgin, make sure you're already logged in to the https://battle.net/ website.  Your browser window should complain about "The webpage at http://localhost:0/?ST=... can't be reached" which is the correct response; you want to copy-paste the ST=... part of the URL into the Pidgin popup window.

If instead you see a broken login screen with a blue button that says "Log in to Blizzard" then open the developer tools (Ctrl+Shift+i) and run `document.getElementById('login-input-container').className = '' `

## Compiling ##
You'll need development packages for libpurple, glib and libprotobuf-c to be able to compile.

## Debian/Ubuntu ##
Run the following commands from a terminal

```
#!sh
sudo apt-get install libpurple-dev libglib2.0-dev libprotobuf-c-dev protobuf-c-compiler mercurial make;
git clone https://github.com/EionRobb/purple-battlenet/ && cd purple-battlenet;
make && sudo make install
```

## Windows ##
Development builds of Windows dll's live at https://eion.robbmob.com/libbattlenet.dll (you'll also need [libprotobuf-c-1.dll](https://eion.robbmob.com/libprotobuf-c-1.dll) in your Pidgin folder)

## Do you like this plugin? ##
[Send me $1](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PZMBF2QVF69GA) to say thanks
