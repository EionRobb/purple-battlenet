
PIDGIN_TREE_TOP ?= ../pidgin-2.10.11
PIDGIN3_TREE_TOP ?= ../pidgin-main
LIBPURPLE_DIR ?= $(PIDGIN_TREE_TOP)/libpurple
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev
PROTOBUF_C_DIR ?= $(WIN32_DEV_TOP)/protobuf-c-Release-2.6

WIN32_CC ?= $(WIN32_DEV_TOP)/mingw-4.7.2/bin/gcc

PROTOC_C ?= protoc-c
PKG_CONFIG ?= pkg-config

REVISION_ID = $(shell hg id -i)
REVISION_NUMBER = $(shell hg id -n)
ifneq ($(REVISION_ID),)
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d).git.r$(REVISION_NUMBER).$(REVISION_ID)
else
PLUGIN_VERSION ?= 0.9.$(shell date +%Y.%m.%d)
endif

CFLAGS	?= -O2 -g -pipe -Wall -DBATTLENET_PLUGIN_VERSION='"$(PLUGIN_VERSION)"'
LDFLAGS ?= -Wl,-z,relro 

# Do some nasty OS and purple version detection
ifeq ($(OS),Windows_NT)
  BATTLENET_TARGET = libbattlenet.dll
  BATTLENET_DEST = "$(PROGRAMFILES)/Pidgin/plugins"
  BATTLENET_ICONS_DEST = "$(PROGRAMFILES)/Pidgin/pixmaps/pidgin/protocols"
else

  UNAME_S := $(shell uname -s)

  #.. There are special flags we need for OSX
  ifeq ($(UNAME_S), Darwin)
    #
    #.. /opt/local/include and subdirs are included here to ensure this compiles
    #   for folks using Macports.  I believe Homebrew uses /usr/local/include
    #   so things should "just work".  You *must* make sure your packages are
    #   all up to date or you will most likely get compilation errors.
    #
    INCLUDES = -I/opt/local/include -lz $(OS)

    CC = gcc
  else
    CC ?= gcc
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists libprotobuf-c && echo "true"),true)
    PROTOBUF_OPTS := $(shell $(PKG_CONFIG) --cflags --libs libprotobuf-c)
  else
    PROTOBUF_OPTS := -I/usr/include/google -I/usr/include/google/protobuf-c -lprotobuf-c
  endif

  ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
    ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
      BATTLENET_TARGET = FAILNOPURPLE
      BATTLENET_DEST =
	  BATTLENET_ICONS_DEST =
    else
      BATTLENET_TARGET = libbattlenet.so
      BATTLENET_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
	  BATTLENET_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
    endif
  else
    BATTLENET_TARGET = libbattlenet3.so
    BATTLENET_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
	BATTLENET_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
  endif
endif

WIN32_CFLAGS = -I$(WIN32_DEV_TOP)/glib-2.28.8/include -I$(WIN32_DEV_TOP)/glib-2.28.8/include/glib-2.0 -I$(WIN32_DEV_TOP)/glib-2.28.8/lib/glib-2.0/include -I$(WIN32_DEV_TOP)/protobuf-c-Release-2.6/include -DENABLE_NLS -DBATTLENET_PLUGIN_VERSION='"$(PLUGIN_VERSION)"' -Wall -Wextra -Werror -Wno-deprecated-declarations -Wno-unused-parameter -fno-strict-aliasing -Wformat -I.
WIN32_LDFLAGS = -L$(WIN32_DEV_TOP)/glib-2.28.8/lib -L$(PROTOBUF_C_DIR)/bin -lpurple -lintl -lglib-2.0 -lgobject-2.0 -g -ggdb -static-libgcc -lz -lprotobuf-c-1
WIN32_PIDGIN2_CFLAGS = -I$(PIDGIN_TREE_TOP)/libpurple -I$(PIDGIN_TREE_TOP) $(WIN32_CFLAGS)
WIN32_PIDGIN3_CFLAGS = -I$(PIDGIN3_TREE_TOP)/libpurple -I$(PIDGIN3_TREE_TOP) -I$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_CFLAGS)
WIN32_PIDGIN2_LDFLAGS = -L$(PIDGIN_TREE_TOP)/libpurple $(WIN32_LDFLAGS)
WIN32_PIDGIN3_LDFLAGS = -L$(PIDGIN3_TREE_TOP)/libpurple -L$(WIN32_DEV_TOP)/gplugin-dev/gplugin $(WIN32_LDFLAGS) -lgplugin

C_FILES := 
PURPLE_COMPAT_FILES := 
PURPLE_C_FILES := libbattlenet.c $(C_FILES)
BATTLENET_PROTOS := bnet/*.pb-c.c


.PHONY:	all install FAILNOPURPLE clean install-icons

all: $(BATTLENET_TARGET)

$(BATTLENET_PROTOS): bnet/*.proto
	$(PROTOC_C) --c_out=. bnet/*.proto

libbattlenet.so: $(BATTLENET_PROTOS) $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -I. -shared -o $@ $^ $(LDFLAGS) $(PROTOBUF_OPTS) `$(PKG_CONFIG) purple glib-2.0 --libs --cflags`  $(INCLUDES) -Ipurple2compat -g -ggdb

libbattlenet3.so: $(BATTLENET_PROTOS) $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -I. -shared -o $@ $^ $(LDFLAGS) $(PROTOBUF_OPTS) `$(PKG_CONFIG) purple-3 glib-2.0 --libs --cflags` $(INCLUDES)  -g -ggdb

libbattlenet.dll: $(BATTLENET_PROTOS) $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN2_CFLAGS) $(WIN32_PIDGIN2_LDFLAGS) -Ipurple2compat

libbattlenet3.dll: $(BATTLENET_PROTOS) $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(WIN32_CC) -O0 -g -ggdb -shared -o $@ $^ $(WIN32_PIDGIN3_CFLAGS) $(WIN32_PIDGIN3_LDFLAGS)

install: $(BATTLENET_TARGET) install-icons
	mkdir -p $(BATTLENET_DEST)
	install -p $(BATTLENET_TARGET) $(BATTLENET_DEST)

install-icons: battlenet16.png battlenet22.png battlenet48.png
	mkdir -p $(BATTLENET_ICONS_DEST)/16
	mkdir -p $(BATTLENET_ICONS_DEST)/22
	mkdir -p $(BATTLENET_ICONS_DEST)/48
	install battlenet16.png $(BATTLENET_ICONS_DEST)/16/battlenet.png
	install battlenet22.png $(BATTLENET_ICONS_DEST)/22/battlenet.png
	install battlenet48.png $(BATTLENET_ICONS_DEST)/48/battlenet.png

FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(BATTLENET_TARGET) 

