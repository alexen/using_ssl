PRJDIRS := ssl_server ssl_client
INCLUDE_DIRS := -I$(PWD)
export CPPFLAGS := -std=c++11 -Wall -Werror -Wpedantic -Wextra -g3 -gdwarf-2 $(INCLUDE_DIRS)

all:
	for DIR in $(PRJDIRS); do $(MAKE) -C $$DIR all; done

clean:
	for DIR in $(PRJDIRS); do $(MAKE) -C $$DIR clean; done
