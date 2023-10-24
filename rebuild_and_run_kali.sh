DOCKER_DIR='~/docker/kali'

if [[ ! -d $DOCKER_DIR ]]; then
    mkdir -p $DOCKER_DIR/config
    mkdir -p $DOCKER_DIR/Shared
fi

docker-compose build kali-m1
docker-compose run --service-ports --rm kali-m1