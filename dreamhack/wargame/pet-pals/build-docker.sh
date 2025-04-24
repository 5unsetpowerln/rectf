#!/bin/bash
docker rm -f ctf-docker-deploy
docker build -t ctf-docker-deploy .
docker run --name=ctf-docker-deploy --privileged --rm -p1337:1337 -it ctf-docker-deploy
