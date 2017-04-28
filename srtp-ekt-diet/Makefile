

SRC  := $(wildcard draft-*.xml)

VERSION = 04

HTML := $(patsubst %.xml,%-$(VERSION).html,$(SRC))
TXT  := $(patsubst %.xml,%-$(VERSION).txt,$(SRC))
DIF  := $(patsubst %.xml,%-$(VERSION).diff.html,$(SRC))
PDF  := $(patsubst %.xml,%-$(VERSION).pdf,$(SRC))

all: $(HTML) $(TXT)

diff: $(DIF)

clean:
	rm -f *~ draft*.html draft*pdf draft*txt

%-$(VERSION).html: %.xml
	xml2rfc $^ --html -o $@

%-$(VERSION).txt: %.xml
	xml2rfc $^ --text -o $@

%.diff.html: %.txt
	htmlwdiff  $^.old $^ >  $@

%.pdf: %.html  $(SVG)
	wkpdf -p letter -s $^ -o $@




