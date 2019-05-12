# This `Makefile` is intended for Cowrie developers.

# Dummy target `all`
all:

test:
	tox

build:
	python setup.py build sdist bdist

docs:
	make -C docs html

lint:
	tox -e lint

clean:
	rm -rf _trial_temp build dist

pip-upgrade:
	pip install --upgrade -r requirements.txt

pip-check:
	pip check
