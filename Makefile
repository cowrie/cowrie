# This `Makefile` is intended for Cowrie developers.

# Dummy target `all`
.PHONY: all
all:

.PHONY: test
test:
	tox

.PHONY: build
build:
	python setup.py build sdist bdist

.PHONY: docs
docs:
	make -C docs html

.PHONY: lint
lint:
	tox -e lint

.PHONY: clean
clean:
	rm -rf _trial_temp build dist .tox
	make -C docs clean

.PHONY: pre-commit
pre-commit:
	pre-commit run --all-files

.PHONY: pip-upgrade
pip-upgrade:
	pip install --upgrade -r requirements.txt

.PHONY: pip-check
pip-check:
	pip check

# This assumes two remotes, one is `origin`, your fork. The second is `cowrie` the main project
.PHONY: git-remote
git-remote:
	git remote add cowrie https://github.com/cowrie/cowrie

.PHONY: dependency-upgrade
dependency-upgrade:
	git checkout master
	-git branch -D "dependency-upgrade-`date -u +%Y-%m-%d`"
	git checkout -b "dependency-upgrade-`date -u +%Y-%m-%d`"
	pur -r requirements.txt
	pur -r requirements-dev.txt
	pur --skip csirtgsdk -r requirements-output.txt
	git commit -m "dependency upgrade `date -u`" requirements*.txt
