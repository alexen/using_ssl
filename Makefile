TARGET := using_ssl

SRCDIR := src
HDRS := $(wildcard $(SRCDIR)/*.h)
CPPS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(CPPS:.cpp=.o)

CPPFLAGS := -std=c++11 -Wall -Werror -Wpedantic -Wextra -g3 -gdwarf-2

LIBDIRS :=
LIBS := -lssl -lcrypto -lboost_system

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LIBDIRS) $(LIBS)

clean:
	rm -f $(TARGET) $(OBJS)
