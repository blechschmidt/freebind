SELF := $(lastword $(MAKEFILE_LIST)) # Source: http://stackoverflow.com/a/27132934/778421

default:
	mkdir -p bin
	gcc -g -shared -fPIC freebind.c -o bin/freebind.so -ldl
tests:
	mkdir -p bin
	gcc tests.c -o bin/tests
clean:
	rm -r bin
install:
	@$(MAKE) -f $(SELF) default
	cp bin/freebind.so /usr/local/lib/
