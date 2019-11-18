build:
	python setup.py sdist bdist_wheel

upload:
	python3 -m twine upload --verbose dist/*

clean:
	rm -rf build sdist dist
