# ISO15118

Python Implementation of the ISO 15118 -2 [^1] and -20 [^2] protocols

## How to fire it up :fire:

The ISO 15118 -2 and -20 code lives in the directory `iso15118`.
The primary dependencies to install the project are the following:

> - Linux Distro (Non-Linux Systems are not supported)
> - Poetry [^3]
> - Python >= 3.7

Also, since the project depends on external custom packages, it is necessary
to set the credentials for the Switch PYPI server as ENVs:
   ```shell
   $ export PYPI_USER=****
   $ export PYPI_PASS=****
   ```

Contact André <andre@switch-ev.com> if you require the credentials.

There are two recommended ways of running the project:

1. Building and running the docker file:

   ```bash
   $ make build
   $ make dev
   ```
   Currently, only SECC will be spawned as the goal of JOSEV is to run iso15118
   as an SECC


2. Local Installation
   
   Install JRE engine with the following command:
   ```bash
   apt update && apt install -y default-jre

   ```
   The JRE engine is only a temporary requirement until we replace the Java-based EXI codec (EXIficient)[^4] with our own RUST-based EXI codec.
   
   Install the module using `poetry` and run the main script related
   to the EVCC or SECC instance you want to run. Switch to the iso15118 directory
   and run:
   ```bash
   $ poetry update
   $ poetry install
   $ python iso15118/secc/start_secc.py # or python iso15118/evcc/start_evcc.py
   ```
   For convenience, the Makefile, present in the project, helps you to run these
   steps. Thus, in the terminal run:
   ```bash
   $ make install-local
   $ make run-secc
   ```
   This will call the poetry commands above and run the start script of the
   secc.

Option number `1` has the advantage of running within Docker, where everything
is fired up automatically, including tests and linting. Currently, the 
docker-compose does not set the `network-mode` as 'host', but this may be 
required in order to bridge correctly IPv6 frames.

The project also requires an MQTT broker connection, so be sure to set up
a broker correctly and to add the necessary credentials and URL.

For more information about the MQTT API used by Switch, please contact us.

Finally, the project includes a few configuration variables whose default
values can be modified by setting them as environmental variables.
The following table provides a few of the available variables:

| ENV                        | Default Value         | Description                                                                              |
| -------------------------- | --------------------- | ---------------------------------------------------------------------------------------- |
| NETWORK_INTERFACE          | `eth0`                | HomePlug Green PHY Network Interface from which the high-level communication (HLC) will be established |
| MQTT_HOST                  | `localhost`           | MQTT Broker URL                                                                          |
| MQTT_PORT                  | `9001`                | MQTT Broker PORT                                                                          |
| MQTT_USER                  | `None`                | Username for Client Authorization                                                     |
| MQTT_PASS                  | `None`                | Password for Client Authorization
| 15118_MQTT_SUBSCRIBE_TOPIC | `iso15118/cs`         | Mqtt Subscription Topic
| 15118_MQTT_PUBLISH_TOPIC   | `iso15118/josev`      | Mqtt Publish Topic
| REDIS_HOST                 | `localhost`           | Redis Host URL
| REDIS_PORT                 | `10001`               | Redis Port
|

The project includes an environment file for dev purposes on the root directoy
`.env.development`, which contains all settings that can be set.

In order to run the project in production, an `.env` file must be created with
the desired settings. This means, if development settings are desired, one can
simply copy the content of `.env.development` to `.env`.

If Docker is used, the command `make run` will try to get the `.env` file;
The command `make dev` will fetch the contents of `.env.development`.


## Integration Test with an EV Simulator

Since the project includes both the SECC and EVCC side, it is possible to test
your application starting both services. Similar to the SECC, we can start the
EVCC side as follows:

```bash
$ make install-local
$ make run-evcc
```

This integration test was tested under:

- Linux - Ubuntu and Debian distros
- MacOs

[^1]: https://www.iso.org/standard/55366.html
[^2]: https://www.switch-ev.com/news-and-events/new-features-and-timeline-for-iso15118-20
[^3]: https://python-poetry.org/docs/#installation
[^4]: https://exificient.github.io/
