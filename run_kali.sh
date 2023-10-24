DOCKER_DIR='../DockerShare/docker'

if [[ ! -d $DOCKER_DIR ]]; then
    mkdir -p $DOCKER_DIR/config
    mkdir -p $DOCKER_DIR/Shared
fi

docker-compose run --service-ports --rm kali-m1
