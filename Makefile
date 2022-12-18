
CC=gcc  #compiler
CFLAGS = -Wall
LDFLAGS = -lpcap
OBJFILES = pcap_ex.o  
TARGET= pcap_ex #target file name
 
all:$(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
 
clean:
	rm -rf $(OBJFILES) $(TARGET) *~