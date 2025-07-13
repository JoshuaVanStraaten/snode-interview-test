# Snode-interview-test

## Overview
Normalization of Fortigate firewall data (`input.log`). The firewall data
consists of `authentication`, `configuration`and `firewall` logs which are
normalized according to a respective schema.

## Run the application
The application is wrapped in a docker container for convenience. Prior to
running the application, ensure docker is installed. If docker is not installed,
the following link to [install docker](https://docs.docker.com/engine/install/)
can be followed. Once installed, simply run the following in the `root` of the
repo:

```shell
# pwd: ../snode-interview-test/
docker-compose up
```

## View the output logs
Once the `docker-compose` has run, the `output.log` will be within:
`snode-interview-test/outputs/output.log`. An example `output.log` generated
using this application is located in
`snode-interview-test/outputs/examples/output.log`, which may be used as a
reference.
