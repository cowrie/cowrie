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

# This assumes two remotes, one is `origin`, your fork. The second is `cowrie` the main project
git-remote:
	git remote add cowrie https://github.com/cowrie/cowrie

dependency-upgrade:
	git checkout master
	git checkout -b "dependency-upgrade-`date +%Y-%m-%d`"
	pur -r requirements.txt
	pur -r requirements-dev.txt
	pur -r requirements-output.txt
	git commit -m "dependency upgrade `date`" requirements*.txt
