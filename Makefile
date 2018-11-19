SHELL := /bin/bash
PLATFORM := $(shell go env GOOS)
ARCH := $(shell go env GOARCH)
GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin
VERSION := $(shell cat VERSION)
VERSION_FLAGS := -i -v -ldflags="-X main.version=$(VERSION)"

.PHONY: build clean dep install

build: awsauthorize

install: build
	install -m 755 awsauthorize $(GOBIN)

clean:
	rm -rf awsauthorize

awsauthorize: cmd/awsauthorize VERSION
	DEP_BUILD_PLATFORMS=$(PLATFORM) DEP_BUILD_ARCHS=$(ARCH) go build $(VERSION_FLAGS) ./...

dep: Gopkg.lock
	@go fmt ./...
	@dep ensure

Gopkg.lock: Gopkg.toml
	dep ensure --update