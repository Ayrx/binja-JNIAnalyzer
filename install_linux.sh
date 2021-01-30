#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ln -sf $DIR $HOME/.binaryninja/plugins/jnianalyzer
