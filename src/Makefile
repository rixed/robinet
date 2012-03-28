.SUFFIXES: .tmpl .html

CPP = cpp -pipe -P -std=c89
# c89 avoids looking // as a comment :-)

TMPLS = $(wildcard *.tmpl)
HTMLS = $(subst .tmpl,.html,$(TMPLS))

all: $(HTMLS)

.tmpl.html:
	$(CPP) -o $@ $<

$(HTMLS): $(wildcard *.inc)

.PHONY: clean install

clean:
	rm -f *.html

install: all
	cp *.html ../
