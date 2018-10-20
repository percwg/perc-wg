
#   https://pypi.python.org/pypi/xml2rfc
xml2rfc ?= xml2rfc
#   https://github.com/cabo/kramdown-rfc2629
kramdown-rfc2629 ?= kramdown-rfc2629
#  mmark (https://github.com/mmarkdown/mmark)
mmark ?= mmark

DRAFT    = draft-ietf-perc-dtls-tunnel
VERSION  = $(shell grep 'value.*=.*"$(DRAFT)-[0-9]\+"' $(DRAFT).md | head -1 | sed 's/.*"$(DRAFT)-\([0-9]\+\)".*/\1/')
MMARKVER = $(shell mmark -version | sed 's/\..*//')

.PHONY: all clean diff
.PRECIOUS: %.xml

ifeq ($(MMARKVER), 2)
all: $(DRAFT)-$(VERSION).txt $(DRAFT)-$(VERSION).html

diff: $(DRAFT).diff.html

clean:
	-rm -f $(DRAFT)-$(VERSION).{txt,html,xml,pdf} $(DRAFT).diff.html

%.txt: %.xml
	$(xml2rfc) $< -o $@ --text

%.html: %.xml
	$(xml2rfc) $< -o $@ --html

$(DRAFT)-$(VERSION).xml: $(DRAFT).md
	mmark -2 $^ > $@

$(DRAFT).diff.html: $(DRAFT)-$(VERSION).txt $(DRAFT)-old.txt
	htmlwdiff   $(DRAFT)-old.txt   $(DRAFT)-$(VERSION).txt >   $(DRAFT).diff.html
else
all: $(DRAFT)-$(VERSION).txt $(DRAFT)-$(VERSION).html
	$(error mmark version 2 is required)
endif
