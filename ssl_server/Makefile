TARGET := ssl_server

SRCDIR := src
HDRS := $(wildcard $(SRCDIR)/*.h)
CPPS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(CPPS:.cpp=.o)

LIBDIRS :=
LIBS := -lssl -lcrypto -lpthread

CPPFLAGS += -std=c++11

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LIBDIRS) $(LIBS)

clean:
	rm -f $(TARGET) $(OBJS)
