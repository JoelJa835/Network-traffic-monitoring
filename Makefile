all: 
	gcc pcap_ex.c -o pcap_ex -O1 -lpcap

clean:
	rm -rf pcap_ex
