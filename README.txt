In order to setup the docker, one should have installed docker desktop.
then run the command from the orecale_docker dir:
to build for the first time: docker build -t bleichenbacher-oracle .
to run after built once: docker run --rm -p 5000:5000 bleichenbacher-oracle (--rm for not saving state)