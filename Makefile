# The shell to run the makefile with must be defined to work properly in Linux systems
SHELL := /bin/bash

# all the recipes are phony (no files to check).
.PHONY: .install-poetry docs tests build dev run poetry-update poetry-install install-local run-evcc run-secc run-ocpp mypy reformat black flake8 code-quality

export PATH := ${HOME}/.local/bin:$(PATH)

.DEFAULT_GOAL := help

IS_POETRY := $(shell pip freeze | grep "poetry==")


help:
	@echo "Please use 'make <target>', where <target> is one of"
	@echo ""
	@echo "  help                             outputs this helper"
	@echo "  build                            builds the project using Docker"
	@echo "  dev                              runs secc and redis in dev version, using Docker"
	@echo "  run                              runs secc and redis in prod version, using Docker"
	@echo "  install-local                    uses poetry to update and install iso15118 locally, including dependencies"
	@echo "  run-secc                         runs the secc project locally"
	@echo "  run-evcc                         runs the evcc project locally"
	@echo "  reformat                         reformats the code with isort and black"
	@echo "  mypy                             installs the dependencies in the env"
	@echo "  code-quality                     runs mypy, flake8, black and reformats the code"
	@echo "  tests                            run all the tests, locally"
	@echo "  release version=<mj.mn.p>        bumps the project version to <mj.mn.p>, using poetry;"
	@echo "                                   If no version is provided, poetry outputs the current project version"
	@echo ""
	@echo "Check the Makefile to know exactly what each target is doing."


.install-poetry:
	@if [ -z ${IS_POETRY} ]; then pip install poetry; fi

docs: .install-poetry
	# poetry run sphinx-build -b html docs/source docs/build

tests: .install-poetry
	#poetry run flake8 pytest -vv tests
	poetry run pytest -vv tests

.generate_v2_certs:
	cd iso15118/shared/pki; ./create_certs.sh -v iso-2

.generate_v20_certs:
	cd iso15118/shared/pki; ./create_certs.sh -v iso-20

build: .generate_v2_certs
	@# `xargs` will copy the Dockerfile template, so that it can be individually
	@# used by the secc and evcc services
	@xargs -n 1 cp -v template.Dockerfile<<<"iso15118/evcc/Dockerfile iso15118/secc/Dockerfile"
	@# The following command will convert: 's/secc/secc/g' -> 's/secc/evcc/g',
	@# in the evcc Dockerfile.
	@# This conversion is required, otherwise we wouldn't be able to spawn the evcc start script.
	@# @ is used as a separator and allows us to escape '/', so we can substitute the '/' itself
	@sed -i.bkp 's@/secc/g@/evcc/g@g' iso15118/evcc/Dockerfile
	docker-compose build  --build-arg PYPI_USER=${PYPI_USER} --build-arg PYPI_PASS=${PYPI_PASS}

dev:
	# the dev file apply changes to the original compose file
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

run:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up

poetry-update:
	poetry update

install-local:
	pip install .

run-evcc:
	$(shell which python) iso15118/evcc/start_evcc.py

run-secc:
	$(shell which python) iso15118/secc/start_secc.py


mypy:
	mypy --config-file mypy.ini iso15118 tests

reformat:
	isort iso15118 tests && black --line-length=88 iso15118 tests

black:
	black --check --diff --line-length=88 iso15118 tests

flake8:
	flake8 --config .flake8 iso15118 tests

code-quality: reformat mypy black flake8

release: .install-poetry
	@echo "Please remember to update the CHANGELOG.md, before tagging the release"
	@poetry version ${version}
