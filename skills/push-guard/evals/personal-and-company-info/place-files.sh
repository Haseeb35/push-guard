#!/usr/bin/env bash
# Builds the throwaway test repo (with FAKE secrets) in the current folder.
set -eu
python3 "$(dirname "$0")/files/make_repo.py" personal-and-company-info . || python "$(dirname "$0")/files/make_repo.py" personal-and-company-info .
