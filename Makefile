PRJDIRS := ssl_server ssl_client other

INCLUDE_DIRS := -I$(PWD)
DEBUG_OPTS := -g3 -gdwarf-2

export CPPFLAGS := -Wall -Werror -Wpedantic -Wextra $(DEBUG_OPTS) $(INCLUDE_DIRS)

all:
	for DIR in $(PRJDIRS); do $(MAKE) -C $$DIR all; done

clean:
	for DIR in $(PRJDIRS); do $(MAKE) -C $$DIR clean; done
