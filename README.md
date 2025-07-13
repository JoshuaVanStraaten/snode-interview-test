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
docker-compose up --build
```

Vector is configured to sink the transformed logs to an Elasticsearch database
with a Kibana supervisor. Ensure the following:

**Verify Elasticsearch is running**:
- Open your browser and navigate to [http://localhost:9200](http://localhost:9200).
  You should see a JSON response with cluster information such as:
  ```json
    {
    "name" : "f1d99c890723",
    "cluster_name" : "docker-cluster",
    "cluster_uuid" : "IuXpNGQrQ7e7_EamvhpB1w",
    "version" : {
        "number" : "8.14.0",
        "build_flavor" : "default",
        "build_type" : "docker",
        "build_hash" : "8d96bbe3bf5fed931f3119733895458eab75dca9",
        "build_date" : "2024-06-03T10:05:49.073003402Z",
        "build_snapshot" : false,
        "lucene_version" : "9.10.0",
        "minimum_wire_compatibility_version" : "7.17.0",
        "minimum_index_compatibility_version" : "7.0.0"
    },
    "tagline" : "You Know, for Search"
    }
  ```
**Access Kibana**:
- Open your browser and navigate to [http://localhost:5601](http://localhost:5601).

## View the output logs
At the point, the output logs are within the Elasticsearch database. To view
these log entries, this can be done via Kibana:

* If it's your first time, click "Explore on my own" or similar.
* In the left-hand navigation, go to **Stack Management** -> **Kibana**
-> **Data Views**.
* Click "Create data view" and fill in the fields as follows:
    ![Create data view](/snode-interview-test/images/create-data-view.png)
* Click "Save data view to Kibana".
* Once created, go to **Analytics** -> **Discover** to view your normalized
  Fortigate logs.
* If nothing displays, there should be a blue button **View all matches**, click
  the button and the logs will display.

An example `output.log` generated using this application is also located in
`snode-interview-test/outputs/examples/output.log`, which may be used as a
reference.

## Clean Up
The docker compose can be shutdown as follows:

```shell
# Cntrl + C -> Stops the containers
# Remove the containers
docker-compose down
# OPTIONAL: Clean persistent log data from ElasticSearch
docker volume rm snode-interview-test_esdata
```
