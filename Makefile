SELF := $(lastword $(MAKEFILE_LIST)) # Source: http://stackoverflow.com/a/27132934/778421

default:
	mkdir -p bin
	gcc -Wall -shared -fPIC freebind.c -o bin/freebind.so -ldl
	gcc -Wall preloader.c -o bin/freebind
	gcc -Wall packetrand.c -o bin/packetrand -lnetfilter_queue
tests:
	mkdir -p bin
	gcc tests.c -o bin/tests
clean:
	rm -r bin
install:
	@$(MAKE) -f $(SELF) default
	cp bin/freebind.so /usr/local/lib/
	cp bin/freebind /usr/local/bin/
	cp bin/packetrand /usr/local/bin/
