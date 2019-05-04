
# Dummy target `all`
all:

# Note --aplication-import-names only works on Python3
test: 
	flake8 --count --application-import-names cowrie --max-line-length=120 --statistics .
	PYTHONPATH=src trial cowrie

build:
	python setup.py build sdist bdist

docs:
	make -C docs html
