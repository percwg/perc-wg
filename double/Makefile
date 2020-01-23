
#   https://pypi.python.org/pypi/xml2rfc
xml2rfc ?= xml2rfc
#   https://github.com/cabo/kramdown-rfc2629
kramdown-rfc2629 ?= kramdown-rfc2629
#  mmark (https://github.com/miekg/mmark)
mmark ?= mmark

DRAFT = draft-ietf-perc-double
VERSION = 12

.PHONY: all clean diff
.PRECIOUS: %.xml

all: $(DRAFT)-$(VERSION).txt $(DRAFT)-$(VERSION).html 

diff: $(DRAFT).diff.html

clean:
	-rm -f $(DRAFT)-??.{txt,html,xml,pdf} $(DRAFT).diff.html

%.txt: %.xml
	$(xml2rfc) $< -o $@ --text

%.html: %.xml
	$(xml2rfc) $< -o $@ --html

$(DRAFT)-$(VERSION).xml: $(DRAFT).md 
	mmark -xml2 -page $^ $@ 

$(DRAFT).diff.html: $(DRAFT)-$(VERSION).txt $(DRAFT)-old.txt 
	htmlwdiff   $(DRAFT)-old.txt   $(DRAFT)-$(VERSION).txt >   $(DRAFT).diff.html


rfc8723.diff.html: rfc8723.txt rfc8723-old.txt 
	htmlwdiff   rfc8723-old.txt   rfc8723.txt >   rfc8723.diff.html


diag.svg: diag.asc Makefile 
	~/.cargo/bin/svgbob < diag.asc |\
		sed -e 's/<rect.*\/>//g' |\
		sed -e 's/width="576"/width="576" version="1.1" baseProfile="tiny"/g' |\
		sed -e 's/<svg /<\!DOCTYPE svg PUBLIC "-\/\/W3C\/\/DTD SVG 1.1 Tiny\/\/EN" "http:\/\/www.w3.org\/Graphics\/SVG\/1.1\/DTD\/svg11-tiny.dtd"\> <svg /g' |\
		tr -d '\n' |\
		sed -e 's/<line/<line stroke="black" stroke-width="2" /g' |\
		sed -e 's/<defs>.*<\/defs>//g' |\
		sed -e 's/<style.*<\/style>//g' |\
		xmllint --format - |\
		sed -e 's/version="1.0"/version="1.0" encoding="UTF-8"/g' |\
		sed -e 's/class="bob" //g' |\
		sed -e 's/marker-end="[a-zA-Z()#]*"//g' |\
		sed -e 's/arial/monospace/g' |\
		cat > diag.svg

