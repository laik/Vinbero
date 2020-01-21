.DEFAULT_GOAL := all

BIN_DIR := ${PWD}/bin
export PATH := ${BIN_DIR}:${PATH}

#  Commands
#-----------------------------------------------
.PHONY: all
all:
	env GOOS=linux GOARCH=amd64 go build main.go

