#!/bin/bash

# helper script to update all things related to protobuf proto

protoc --python_out=. probe.proto

cd static/js
if [[ ! -d node_modules ]]; then
	npm install
fi
PATH=$PATH:./node_modules/protoc-gen-js/bin
protoc --js_out=import_style=commonjs,binary:. --proto_path ../../ probe.proto

npm run build
