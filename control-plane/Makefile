.PHONY: build-requirements
build-requirements:
	python3 -m pip install -r build-requirements.txt

.PHONY: lint
lint:
	@echo "> Running pylint ..."
	python3 -m pylint -vr vppconf

.PHONY: test
unittest:
	@echo "> Running unittest ..."
	python3 -m unittest -bvv

.PHONY: unittest-coverage
unittest-coverage:
	@echo "> Running unittest coverage ..."
	coverage3 run -m unittest -bvv
	coverage3 html --include 'vppconf/*'

.PHONY: securityscan
securityscan:
	@echo "> Running bandit ..."
	python3 -m bandit -r vppconf

.PHONY: tests
tests: lint unittest securityscan

.PHONY: build
build: build-requirements
	python3 -m build

.PHONY: clean
clean:
	rm -rf build dist htmlcov vppconf.egg-info

##############################################################################
## THE END
