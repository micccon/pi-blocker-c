all: dns http

dns:
	$(MAKE) -C dns

http:
	$(MAKE) -C http

clean:
	$(MAKE) -C dns clean
	$(MAKE) -C http clean

run: all
	./start_layer7.sh

.PHONY: all dns http clean run
