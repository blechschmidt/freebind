SELF := $(lastword $(MAKEFILE_LIST)) # Source: http://stackoverflow.com/a/27132934/778421

default:
	mkdir -p bin
	gcc -Wall -shared -fPIC src/freebind.c -o bin/freebind.so -ldl
	gcc -Wall src/preloader.c -o bin/freebind
	gcc -Wall src/packetrand.c -o bin/packetrand -lnetfilter_queue
tests:
	mkdir -p bin
	gcc src/tests.c -o bin/tests
clean:
	rm -r bin
install:
	@$(MAKE) -f $(SELF) default
	install -m 0755 bin/freebind.so /usr/local/lib/
	install -m 0755 bin/freebind /usr/local/bin/
	install -m 0755 bin/packetrand /usr/local/bin/
