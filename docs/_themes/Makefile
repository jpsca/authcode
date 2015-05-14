
compile:
	msgfmt -o _locale/es/LC_MESSAGES/lucuma.mo _locale/es/LC_MESSAGES/lucuma.po
	msgfmt -o _locale/es/LC_MESSAGES/sphinx.mo _locale/es/LC_MESSAGES/sphinx.po
	msgfmt -o _locale/en/LC_MESSAGES/lucuma.mo _locale/en/LC_MESSAGES/lucuma.po
	msgfmt -o _locale/en/LC_MESSAGES/sphinx.mo _locale/en/LC_MESSAGES/sphinx.po

extract:
	pybabel extract -F babel.cfg -o _locale/lucuma.pot lucuma

clean:
	rm -f _locale/lucuma.pot
	rm -f _locale/es/LC_MESSAGES/*.mo
	rm -f _locale/en/LC_MESSAGES/*.mo
