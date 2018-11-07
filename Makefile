all: docs

.PHONY: clean
clean:
	find . -name "*.pyc" -delete

.PHONY: docs
docs:
	sphinx-apidoc -f -o docs/source src/ && cd docs && make html && cd ..
