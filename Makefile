# The shell to run the makefile with must be defined to work properly in Linux systems
SHELL := /bin/bash

# all the recipes are phony (no files to check).
.PHONY: .install-poetry docs tests build dev run poetry-update poetry-install install-local run-evcc run-secc run-ocpp mypy reformat black flake8 code-quality

export PATH := ${HOME}/.local/bin:$(PATH)

.DEFAULT_GOAL := help

IS_POETRY := $(shell pip freeze | grep "poetry==")

# Output descriptions of all commands
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
	@echo "  test                             run all the tests, locally"
	@echo "  release version=<mj.mn.p>        bumps the project version to <mj.mn.p>, using poetry;"
	@echo "                                   If no version is provided, poetry outputs the current project version"
	@echo ""
	@echo "Check the Makefile to know exactly what each target is doing."

# Install poetry with pip
.install-poetry:
	@if [ -z ${IS_POETRY} ]; then pip install poetry; fi

# Run pytest with poetry
tests: .install-poetry
	poetry run pytest -vv tests

# Generate test -2 certificates
generate_v2_certs:
	cd iso15118/shared/pki; ./create_certs.sh -v iso-2

# Generate test -20 certificates
generate_v20_certs:
	cd iso15118/shared/pki; ./create_certs.sh -v iso-20

# Build docker images
build: generate_v2_certs
	@# `xargs` will copy the Dockerfile template, so that it can be individually
	@# used by the secc and evcc services
	@xargs -n 1 cp -v template.Dockerfile<<<"iso15118/evcc/Dockerfile iso15118/secc/Dockerfile"
	@# The following command will convert: 's/secc/secc/g' -> 's/secc/evcc/g',
	@# in the evcc Dockerfile.
	@# This conversion is required, otherwise we wouldn't be able to spawn the evcc start script.
	@# @ is used as a separator and allows us to escape '/', so we can substitute the '/' itself
	@sed -i.bkp 's@/secc/g@/evcc/g@g' iso15118/evcc/Dockerfile
	@# Add a delay on EVCC to give SECC time to start up 
	@sed -i'.bkp' -e 's@CMD /venv/bin/iso15118@CMD echo "Waiting for 5 seconds to start EVCC" \&\& sleep 5 \&\& /venv/bin/iso15118@g' iso15118/evcc/Dockerfile
	docker-compose build

# Run using dev env vars
dev:
	# the dev file apply changes to the original compose file
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Run using prod env vars
run:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up

# Update dependencies with poetry
poetry-update:
	poetry update

# Install dependencies with poetry
install-local:
	poetry install

# Use poetry virtual environment
poetry-shell:
	poetry shell

# Run evcc with python
run-evcc:
	poetry run python iso15118/evcc/main.py $(config)

# Run secc with python
run-secc:
	poetry run python iso15118/secc/main.py

# Run pytest on evcc
test-evcc:
	pytest tests/evcc

# Run pytest on secc
test-secc:
	pytest tests/secc

# Run pytest
test:
	poetry run pytest -vv --cov-config .coveragerc --cov-report term-missing  --durations=3 --cov=.

# Run mypy checks
mypy:
	poetry run mypy --config-file mypy.ini iso15118 tests

# Reformat with isort and black
reformat:
	poetry run isort iso15118 tests && poetry run black --line-length=88 iso15118 tests

# Run black checks
black:
	poetry run black --check --diff --line-length=88 iso15118 tests

# Run isort checks
isort:
	poetry run isort --check-only iso15118 tests

# Run flake8 checks
flake8:
	poetry run flake8 --config .flake8 iso15118 tests

# Run black, isort, mypy, & flake8
code-quality: reformat mypy flake8

# Bump project version with poetry
release: .install-poetry
	@echo "Please remember to update the CHANGELOG.md and __init__.py under iso15118 dir, before tagging the release"
	@poetry version ${version}
