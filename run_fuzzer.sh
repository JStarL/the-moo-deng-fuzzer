#!/bin/sh

IMAGE_NAME="moodeng"
CONTAINER_NAME="moodeng"

# clean up any existing images
docker container rm $CONTAINER_NAME
docker image rm localhost/$IMAGE_NAME:latest

# build the image
docker build -t $IMAGE_NAME .

# run the image
docker run -it --name=$CONTAINER_NAME $IMAGE_NAME
