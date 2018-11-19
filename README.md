# AWS Security Group self add

This repository contains a tool to add yourself to a AWS security group

## Getting started

Clone and build from github. Assumes you have set up the Go development environment.
```bash
cd $GOPATH/src
git clone https://github.com/crosseyed/awsallowsself.git

# List available tags
git tag

# Checkout the latest stable tag (master is used for trunk based development)
git checkout $TAG

make build

# Install to $GOPATH/bin
make install
```

Choose or create a security group (SelfAdd) you can add ingress rules to
```bash
awsauthorize --security-group SelfAdd $AWSREGION
```
