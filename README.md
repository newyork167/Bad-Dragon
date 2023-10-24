# Bad-Dragon
Kali setup scripts and common third party repos/tools that can also run on Apple M*


## Docker

The two main options are to either pull straight from docker to run commands

```bash
 docker run --rm -it newyork167/bad-dragon:latest bash
 ```

or via docker-compose which can be ran using the [run_kali.sh](run_kali.sh) script, or manually via

```bash
docker-compose run --service-ports --rm bad-dragon
```