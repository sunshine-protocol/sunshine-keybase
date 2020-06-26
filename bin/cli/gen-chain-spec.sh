#!/bin/sh
NODE=../../target/debug/test-node
$NODE build-spec --dev > chain-spec.json
