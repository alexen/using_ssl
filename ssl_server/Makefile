TARGET := ssl_server

SRCDIR := src
HDRS := $(wildcard $(SRCDIR)/*.h)
CPPS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(CPPS:.cpp=.o)

LIBDIRS :=
LIBS := -lssl -lcrypto -lpthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LIBDIRS) $(LIBS)

clean:
	rm -f $(TARGET) $(OBJS)
