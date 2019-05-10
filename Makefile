
# Dummy target `all`
all:

# Note --aplication-import-names only works on Python3
test: lint
	PYTHONPATH=src trial cowrie

build:
	python setup.py build sdist bdist

docs:
	make -C docs html

lint:
	flake8 --count --application-import-names cowrie --max-line-length=120 --statistics .

clean:
	rm -rf _trial_temp build dist

pip-upgrade:
	pip install --upgrade -r requirements.txt

pip-check:
	pip check
