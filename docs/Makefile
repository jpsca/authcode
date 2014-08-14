# MakeFile for building all the docs at once.
#

.PHONY: all clean html latexpdf epub htmlhelp

langs = en es

html: $(foreach lang,$(langs),html-$(lang))

html-%:
	cd $* && make html LANG=$*

htmlhelp: $(foreach lang,$(langs),htmlhelp-$(lang))

htmlhelp-%:
	cd $* && make htmlhelp LANG=$*

epub: $(foreach lang,$(langs),epub-$(lang))

epub-%:
	cd $* && make epub LANG=$*

latexpdf: $(foreach lang,$(langs),latexpdf-$(lang))

latexpdf-%:
	cd $* && make latexpdf LANG=$*

clean:
	rm -rf _build/

intl:
	cd es && sphinx-intl build

