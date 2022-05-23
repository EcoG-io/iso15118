# Build image
FROM python:3.10.0-buster as build

WORKDIR /usr/src/app

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_VERSION=1.1.11 \
  VIRTUALENV_PIP=21.2.1 \
  MYPY_VERSION=0.930


RUN pip install "poetry==$POETRY_VERSION" "mypy==$MYPY_VERSION"
# pylintrc, coveragerc, poetry.lock and pyproject.toml shall not change very
# often, so it is a good idea to add them as soon as possible
COPY .coveragerc mypy.ini .flake8  ./
COPY poetry.lock pyproject.toml ./
# During make build this sed command is substituted by 's/secc/evcc/g'
RUN sed -i 's/secc/secc/g' pyproject.toml

# Due to an issue with Python 3.10 and poetry, if we use a poetry virtual env,
# we need to disable the option: poetry config experimental.new-installer false
# check https://github.com/python-poetry/poetry/issues/4210
# However, if we run poetry config virtualenvs.create false, then we dont.
# Do not create a virtual poetry env as we already are in an isolated container
RUN poetry config virtualenvs.create false
# Install dependencies and the project in the venv
RUN poetry install --no-interaction --no-ansi

# Copy the project to the system
COPY iso15118/ iso15118/

# Run the tests and linting
COPY tests/ tests/
RUN poetry run black --check --diff --line-length=88 iso15118 tests
RUN poetry run flake8 --config .flake8 iso15118 tests
# RUN poetry run mypy --config-file mypy.ini iso15118 tests
RUN poetry run pytest -vv --cov-config .coveragerc --cov-report term-missing  --durations=3 --cov=.


# Generate the wheel to be used by next stage
RUN poetry build

# The following command when issued leaves the container running forever
# which may be useful for debugging reasons, so it stays here as reference
# CMD exec /bin/bash -c "trap : TERM INT; sleep infinity & wait"

# Runtime image (which is smaller than the build one)
FROM python:3.10.0-buster
WORKDIR /usr/src/app
# Installs Java
RUN apt update && apt install -y default-jre
# create virtualenv
RUN python -m venv /venv
# copy dependencies and wheel from the build stage
COPY --from=build /usr/src/app/dist/ dist/
# This will install the wheel in the venv
RUN /venv/bin/pip install dist/*.whl


# Generating the certs inside the container didn't work (error: Certificate verification failed), but the command is kept
# here so we can investigate this issue later on
# RUN cd /venv/lib/python3.10/site-packages/iso15118/shared/pki && ./create_certs.sh -v iso-2

# This is not the ideal way to provide the certificate chain to the container, but for now it works
COPY --from=build /usr/src/app/iso15118/shared/pki/ /usr/src/app/iso15118/shared/pki/


# This will run the entrypoint script defined in the pyproject.toml
CMD /venv/bin/iso15118
