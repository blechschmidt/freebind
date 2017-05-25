SELF := $(lastword $(MAKEFILE_LIST)) # Source: http://stackoverflow.com/a/27132934/778421

default:
	mkdir -p bin
	gcc -shared -fPIC freebind.c -o bin/freebind.so -ldl
	gcc preloader.c -o bin/freebind
tests:
	mkdir -p bin
	gcc tests.c -o bin/tests
clean:
	rm -r bin
install:
	@$(MAKE) -f $(SELF) default
	cp bin/freebind.so /usr/local/lib/
	cp bin/freebind /usr/local/bin/
