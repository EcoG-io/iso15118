# Build image
FROM python:3.10.0-buster as build

WORKDIR /usr/src/app

ENV PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_VERSION=1.3.2 \
  VIRTUALENV_PIP=21.2.1 \
  MYPY_VERSION=0.930

RUN pip install "poetry==$POETRY_VERSION" "mypy==$MYPY_VERSION"
COPY .coveragerc mypy.ini .flake8 poetry.lock pyproject.toml ./

# During make build this sed command is substituted by 's/secc/evcc/g'
RUN sed -i 's/secc/secc/g' pyproject.toml

# Install dependencies and the project in the venv
RUN poetry install --no-interaction --no-ansi

# Copy the project to the system
COPY iso15118/ iso15118/

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
# Create virtualenv
RUN python -m venv /venv
# Copy dependencies and wheel from the build stage
COPY --from=build /usr/src/app/dist/ dist/
# This will install the wheel in the venv
RUN /venv/bin/pip install dist/*.whl

# Replace with in-container cert generation DevOps#2664
COPY --from=build /usr/src/app/iso15118/shared/pki/ /usr/src/app/iso15118/shared/pki/
COPY --from=build /usr/src/app/iso15118/shared/examples/evcc/iso15118_2/ /usr/src/app/iso15118/shared/examples/evcc/iso15118_2/

RUN /venv/bin/pip install aiofile
# This will run the entrypoint script defined in the pyproject.toml
CMD /venv/bin/iso15118
