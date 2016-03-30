

SRC  := $(wildcard draft-*.xml)

HTML := $(patsubst %.xml,%.html,$(SRC))
TXT  := $(patsubst %.xml,%.txt,$(SRC))
DIF  := $(patsubst %.xml,%.diff.html,$(SRC))
PDF  := $(patsubst %.xml,%.pdf,$(SRC))

all: $(HTML) $(TXT) 

clean:
	rm -f *~ draft*.html draft*pdf draft*txt

%.html: %.xml
	xml2rfc $^ --html

%.txt: %.xml
	xml2rfc $^ --text 

%.diff.html: %.txt
	htmlwdiff  $^.old $^ >  $@

%.pdf: %.html  $(SVG)
	wkpdf -p letter -s $^ -o $@




