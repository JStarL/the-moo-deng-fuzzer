# the-moo-deng-fuzzer installation

 Author:
 Jibitesh Saha(z5280740), Li Li (z5441928), Antheo Raviel Santosa (z5437039), Halliya Hyeryeon UM (z5408331)



# How to build and run the Docker container

## Docker commands

* `docker build -t my-fuzzer .`

* `docker run my-fuzzer`

## Docker command lines to use..

`docker build -t $IMAGE_NAME .`
* build the docker image

`docker run -it $IMAGE_NAME $CONTAINER_NAME`
* instantiates a new container from the image and run the default command

`docker exec -it $CONTAINER_NAME`
* use an existing container and run it
