#!/bin/bash
set -e

mvn clean package
gsutil cp ./jsign/target/jsign-2.1.jar gs://get.rookout.com/jsign-rookout.jar