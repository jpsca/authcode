.PHONY: clean-pyc clean-build

help:
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests quickly with the default Python"
	@echo "testall - run tests on every Python version with tox"
	@echo "coverage - check code coverage with the default Python"
	@echo "publish - package and upload a release"
	@echo "sdist - package"

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
	py.test --cov-config .coveragerc --cov authcode --cov-report html tests/
	open htmlcov/index.html

publish: clean
	python setup.py sdist upload

sdist: clean
	python setup.py sdist
	ls -l dist

wheel: clean
	pip wheel --wheel-dir=wheel .
