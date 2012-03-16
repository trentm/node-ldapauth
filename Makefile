#
# Copyright (c) 2012 Trent Mick
#
# node-ldapauth Makefile
#

#---- Files

JSSTYLE_FILES := $(shell find lib -name *.js)



#---- Targets

all:

.PHONY: cutarelease
cutarelease:
	[[ ! -d tmp ]]   # No 'tmp/' allowed: https://github.com/isaacs/npm/issues/2144
	./tools/cutarelease.py -p ldapauth -f package.json

.PHONY: check-jsstyle
check-jsstyle: $(JSSTYLE_FILES)
	./tools/jsstyle -o indent=2,doxygen,unparenthesized-return=0,blank-after-start-comment=0 $(JSSTYLE_FILES)

.PHONY: check
check: check-jsstyle
	@echo "Check ok."

.PHONY: prepush
prepush: check test
	@echo "Okay to push."
