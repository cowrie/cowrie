# This `Makefile` is intended for Cowrie developers.


# Dummy target `all`
.DEFAULT_GOAL := help
.PHONY: all
all: help
	@echo $(COMMIT)--

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test:
	tox

.PHONY: build
build:
	python setup.py build sdist bdist

.PHONY: docs
docs: ## Create documentation
	make -C docs html

.PHONY: lint
lint: ## Run lint checks
	tox -e lint
	hadolint docker/Dockerfile

.PHONY: clean
clean: ## Clean temporary files
	rm -rf _trial_temp build dist src/_trial_temp src/Cowrie.egg-info
	make -C docs clean

.PHONY: pre-commit
pre-commit: ## Run pre-commit checks
	pre-commit run --all-files

.PHONY: pip-upgrade
pip-upgrade: ## Upgrade environment from requirements.txt
	pip install --upgrade -r requirements.txt

.PHONY: pip-check
pip-check: ## Verify python packages
	pip check

# This assumes two remotes, one is `origin`, your fork. The second is `cowrie` the main project
.PHONY: git-remote
git-remote: ## Add remote git configuration
	git remote add cowrie https://github.com/cowrie/cowrie

.PHONY: pur
pip-pur: ## Upgrade dependencies based on latest packages
	git checkout master
	-git branch -D "dependency-upgrade-`date -u +%Y-%m-%d`"
	git checkout -b "dependency-upgrade-`date -u +%Y-%m-%d`"
	pur -r requirements.txt
	pur -r requirements-dev.txt
	pur -r requirements-output.txt
	git commit -m "dependency upgrade `date -u`" requirements*.txt
# This Makefile is for developers and is not required to run Cowrie

# The binary to build (just the basename).
MODULE := cowrie

# Where to push the docker image.
#REGISTRY ?= docker.pkg.github.com/cowrie/cowrie
REGISTRY ?= cowrie

IMAGE := $(REGISTRY)/$(MODULE)

IMAGENAME := cowrie/cowrie
CONTAINERNAME := cowrie

BUILD_DATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
TAG=$(shell git rev-parse --short=8 HEAD)

.PHONY: docker-build
docker-build: docker/Dockerfile ## Build Docker image
	#docker build -t ${IMAGENAME}:${TAG} --no-cache --build-arg TAG=${TAG} --build-arg BUILD_DATE=${BUILD_DATE} -f docker/Dockerfile .
	docker build -t ${IMAGENAME}:${TAG} --build-arg BUILD_DATE=${BUILD_DATE} -f docker/Dockerfile .

.PHONY: docker-run
docker-run: docker-start ## Run Docker container

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to Docker Hub
	@echo "Pushing image to GitHub Docker Registry...\n"
	docker push $(IMAGE):$(TAG)
	docker tag $(IMAGE):$(TAG) $(IMAGE):latest
	docker push $(IMAGE):latest

.PHONY: docker-start
docker-start: docker-create-volumes ## Start Docker container
	docker run -p 2222:2222/tcp \
		   -p 2223:2223/tcp \
		   -v cowrie-etc:/cowrie/cowrie-git/etc \
		   -v cowrie-var:/cowrie/cowrie-git/var \
		   -d \
		   --cap-drop=ALL \
		   --read-only \
	           --name ${CONTAINERNAME} ${IMAGENAME}:${TAG}

.PHONY: docker-stop
docker-stop: ## Stop Docker Container
	docker stop ${CONTAINERNAME}

.PHONY: docker-rm
docker-rm: docker-stop ## Delete Docker Container
	docker rm ${CONTAINERNAME}

.PHONY: docker-clean
docker-clean: docker-rm ## Clean
	docker rmi ${IMAGENAME}:${TAG}

.PHONY: docker-shell
docker-shell: ## Start shell in running Docker container
	@docker exec -it ${CONTAINERNAME} bash

.PHONY: docker-logs
docker-logs: ## Show Docker container logs
	@docker logs ${CONTAINERNAME}

.PHONY: docker-ps
docker-ps:
	@docker ps -f name=${CONTAINERNAME}

.PHONY: docker-status
docker-status: docker-ps ## List running Docker containers

.PHONY: docker-ip
docker-ip: ## List IP of running Docker container
	@docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${CONTAINERNAME}

.PHONY: docker-create-volumes
docker-create-volumes:
	docker volume create cowrie-var
	docker volume create cowrie-etc
