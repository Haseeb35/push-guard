#!/usr/bin/env bash
# Builds the throwaway test repo (with FAKE secrets) in the current folder.
set -eu
python3 "$(dirname "$0")/files/make_repo.py" clean-repo-no-false-alarms . || python "$(dirname "$0")/files/make_repo.py" clean-repo-no-false-alarms .
