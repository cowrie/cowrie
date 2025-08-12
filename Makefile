# This `Makefile` is intended for Cowrie developers.

# Set default docker binary to docker in path if not specified.
# This allows you to use other container runtimes (such as podman)
# For example, to build with podman: DOCKER=podman make docker-build
DOCKER?=docker

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
	python -m build

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
	python -m pip install --upgrade -r requirements.txt

.PHONY: pip-check
pip-check: ## Verify python packages
	python -m pip check

# This assumes two remotes, one is `origin`, your fork. The second is `cowrie` the main project
.PHONY: git-remote
git-remote: ## Add remote git configuration
	git remote add cowrie https://github.com/cowrie/cowrie

.PHONY: pur
pip-pur: ## Upgrade dependencies based on latest packages
	git checkout main
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

CONTAINERNAME := cowrie
PLATFORM := linux/amd64,linux/arm64

BUILD_DATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
TAG=$(shell git rev-parse --short=8 HEAD)


.PHONY: docker-build
docker-build: docker/Dockerfile ## Build Docker image
	-$(DOCKER) buildx create --name cowrie-builder
	$(DOCKER) buildx use cowrie-builder
	$(DOCKER) buildx build --sbom=true --provenance=true --platform ${PLATFORM} -t ${IMAGE}:${TAG} -t ${IMAGE}:latest --build-arg BUILD_DATE=${BUILD_DATE} -f docker/Dockerfile .

.PHONY: docker-load
docker-load: docker-build ## Load Docker image
	-$(DOCKER) buildx create --name cowrie-builder
	$(DOCKER) buildx use cowrie-builder
	$(DOCKER) buildx build --load -t ${IMAGE}:${TAG} -t ${IMAGE}:latest --build-arg BUILD_DATE=${BUILD_DATE} -f docker/Dockerfile .

.PHONY: docker-build ## Push Docker image
docker-push:  ## Push Docker image to Docker Hub
	-$(DOCKER) buildx create --name cowrie-builder
	@echo "Pushing image to GitHub Docker Registry...\n"
	$(DOCKER) buildx use cowrie-builder
	$(DOCKER) buildx build --sbom=true --provenance=true --platform ${PLATFORM} -t ${IMAGE}:${TAG} -t ${IMAGE}:latest --build-arg BUILD_DATE=${BUILD_DATE} -f docker/Dockerfile --push .

.PHONY: docker-run
docker-run: docker-start ## Run Docker container

.PHONY: docker-start
docker-start: docker-create-volumes ## Start Docker container
	$(DOCKER) run -p 2222:2222/tcp \
		   -p 2223:2223/tcp \
		   -v cowrie-etc:/cowrie/cowrie-git/etc \
		   -v cowrie-var:/cowrie/cowrie-git/var \
		   -d \
		   --cap-drop=ALL \
		   --read-only \
	           --name ${CONTAINERNAME} ${IMAGE}:${TAG}

.PHONY: docker-stop
docker-stop: ## Stop Docker Container
	$(DOCKER) stop ${CONTAINERNAME}

.PHONY: docker-rm
docker-rm: docker-stop ## Delete Docker Container
	$(DOCKER) rm ${CONTAINERNAME}

.PHONY: docker-clean
docker-clean: docker-rm ## Clean
	$(DOCKER) rmi ${IMAGE}:${TAG}

.PHONY: docker-shell
docker-shell: ## Start shell in running Docker container
	@$(DOCKER) exec -it ${CONTAINERNAME} bash

.PHONY: docker-logs
docker-logs: ## Show Docker container logs
	@$(DOCKER) logs ${CONTAINERNAME}

.PHONY: docker-ps
docker-ps:
	@$(DOCKER) ps -f name=${CONTAINERNAME}

.PHONY: docker-status
docker-status: docker-ps ## List running Docker containers

.PHONY: docker-ip
docker-ip: ## List IP of running Docker container
	@$(DOCKER) inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${CONTAINERNAME}

.PHONY: docker-create-volumes
docker-create-volumes:
	$(DOCKER) volume create cowrie-var
	$(DOCKER) volume create cowrie-etc
