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
	@echo "  dev                              runs secc, mqtt and redis in dev version, using Docker"
	@echo "  run                              runs secc, mqtt and redis in prod version, using Docker"
	@echo "  install-local                    uses poetry to update and install iso15118 locally, including dependencies"
	@echo "  run-secc                         runs the secc project locally"
	@echo "  run-evcc                         runs the evcc project locally"
	@echo "  reformat                         reformats the code with isort and black"
	@echo "  mypy                             installs the dependencies in the env"
	@echo "  code-quality                     runs mypy, flake8, black and reformats the code"
	@echo "  tests                            run all the tests, locally"
	@echo ""
	@echo "Check the Makefile to know exactly what each target is doing."


.install-poetry:
	@if [ -z ${IS_POETRY} ]; then pip install poetry; fi

docs: .install-poetry
	# poetry run sphinx-build -b html docs/source docs/build

tests: .install-poetry
	#poetry run flake8 pytest -vv tests
	poetry run pytest -vv tests

build:
	xargs -n 1 cp -v template.Dockerfile<<<"iso15118/evcc/Dockerfile iso15118/secc/Dockerfile"
    # @ is used as a separator and allow us to escape '/', so we can substitute the '/' itself
    # This command will convert: 's/secc/secc/g' -> 's/secc/evcc/g'
	sed -i '.bkp' 's@/secc/g@/evcc/g@g' iso15118/evcc/Dockerfile
	docker-compose build

dev:
    # the dev file apply changes to the original compose file
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

run:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up

poetry-update:
	poetry update

poetry-install:
	poetry update
	poetry install

install-local: poetry-install

run-evcc:
	python iso15118/evcc/start_evcc.py

run-secc:
	python iso15118/secc/start_secc.py


mypy:
	mypy --config-file ../mypy.ini iso15118 tests

reformat:
	isort iso15118 tests && black --line-length=88 iso15118 tests

black:
	black --check --diff --line-length=88 iso15118 tests

flake8:
	flake8 --config ../.flake8 iso15118 tests

code-quality: reformat mypy black flake8
