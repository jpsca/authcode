.PHONY: all

clean: clean-build clean-pyc

clean-build:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

lint:
	flake8 authcode tests --ignore=E501

test:
	py.test -x tests/

test-all:
	tox

coverage:
	py.test -x --cov-config .coveragerc --cov authcode --cov-report html tests/
	open htmlcov/index.html

flake8:
	flake8 authcode tests

publish: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

sdist: clean
	python setup.py sdist
	ls -l dist

wheel: clean
	pip wheel --wheel-dir=wheel .
