#!/usr/bin/env bash

set -e

VERSION=$(grep "<Version>" package.xml | sed -e 's/.*<Version>//' -e 's#</Version>.*##')

mkdir -p build

tar czf \
 build/OAuth2AuthSync-${VERSION}.opm \
 package.xml \
 Kernel