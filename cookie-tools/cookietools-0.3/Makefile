# cookietools project Makefile.

include VERSION


all: build

build:
	cd src ; $(MAKE)
	mv src/cookiesniffer bin/
	@echo "%"
	@echo "%  -- The Cookie Tools v$(VERSION) --"
	@echo "%"
	@echo "%  cookiesniffer: bin/cookiesniffer"
	@echo "%  log analyzers: bin/analyzers/names.sh"
	@echo "%                 bin/analyzers/occurrences.sh"
	@echo "%                 bin/analyzers/vision.sh"
	@echo "%                 bin/analyzers/links.sh"
	@echo "%  cookieserver:  bin/cookieserver/startup.sh"    
	@echo "%"

clean:
	cd src ; $(MAKE) clean
	rm -f bin/cookiesniffer

