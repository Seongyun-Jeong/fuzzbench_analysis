#!/bin/bash

set -ex

PROJECT_NAME=aspell

ENGINE=${1:-libfuzzer}
SANITIZER=${2:-address}

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

# Work out which repo to clone from, inside Docker
if [[ ${TRAVIS_PULL_REQUEST} != "false" ]]
then
    # Pull-request branch
    REPO=${TRAVIS_PULL_REQUEST_SLUG}
    BRANCH=${TRAVIS_PULL_REQUEST_BRANCH}
else
    # Push build.
    REPO=${TRAVIS_REPO_SLUG}
    BRANCH=${TRAVIS_BRANCH}
fi

# Modify the oss-fuzz Dockerfile so that we're checking out the current branch on travis.
sed -i "s@-b master https://github.com/gnuaspell/aspell-fuzz.git@-b ${BRANCH} https://github.com/${REPO}.git@" /tmp/ossfuzz/projects/${PROJECT_NAME}/Dockerfile

# Try and build the fuzzers
pushd /tmp/ossfuzz
python infra/helper.py build_image --pull ${PROJECT_NAME}
python infra/helper.py build_fuzzers --engine=${ENGINE} --sanitizer=${SANITIZER} ${PROJECT_NAME}

if [[ ${SANITIZER} != "coverage" ]]
then
    # Can't verify the coverage build, but can check all other types.
    python infra/helper.py check_build --engine=${ENGINE} --sanitizer=${SANITIZER} ${PROJECT_NAME}
fi

popd
