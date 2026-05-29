#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <new-github-repo-url> <upstream-commit-url> [public|private|internal]"
  echo
  echo "Example:"
  echo "$0 https://github.com/mytreya-rh/mg-7-63242.git https://github.com/mytreya-rh/mg-63242/commit/fdece5030e6cb80158cc5d1c907c29f26a04d7f9 private"
  exit 1
fi

NEW_GITHUB_REPO_URL="$1"
UPSTREAM_COMMIT_URL="$2"
VISIBILITY="${3:-private}"

if ! command -v gh >/dev/null 2>&1; then
  echo "Error: GitHub CLI 'gh' is not installed."
  echo "Install it from: https://cli.github.com/"
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "Error: GitHub CLI is not authenticated."
  echo "Run once: gh auth login"
  exit 1
fi

case "$VISIBILITY" in
  public|private|internal) ;;
  *)
    echo "Error: visibility must be one of: public, private, internal"
    exit 1
    ;;
esac

# Extract owner and repo name from:
#   https://github.com/owner/repo.git
#   https://github.com/owner/repo
#   git@github.com:owner/repo.git
NEW_REPO_PATH="$(
  echo "$NEW_GITHUB_REPO_URL" |
    sed -E 's#^https://github.com/##' |
    sed -E 's#^git@github.com:##' |
    sed -E 's#\.git$##'
)"

OWNER="$(dirname "$NEW_REPO_PATH")"
REPO_NAME="$(basename "$NEW_REPO_PATH")"
DIRECTORY_NAME="$REPO_NAME"

if [ -z "$OWNER" ] || [ -z "$REPO_NAME" ] || [ "$OWNER" = "." ]; then
  echo "Error: could not extract owner/repo from:"
  echo "$NEW_GITHUB_REPO_URL"
  exit 1
fi

# Build SSH URL for pushing so Git does not ask for HTTPS username/password.
NEW_GITHUB_REPO_SSH_URL="git@github.com:${OWNER}/${REPO_NAME}.git"

# Extract upstream repo URL and commit SHA from GitHub commit URL.
UPSTREAM_REPO_URL="$(echo "$UPSTREAM_COMMIT_URL" | sed -E 's#/(commit|commits)/[a-f0-9]+/?$##').git"
COMMIT_SHA="$(echo "$UPSTREAM_COMMIT_URL" | sed -E 's#^.*/(commit|commits)/([a-f0-9]+)/?$#\2#')"

if ! [[ "$COMMIT_SHA" =~ ^[a-f0-9]{7,40}$ ]]; then
  echo "Error: could not extract a valid commit SHA from:"
  echo "$UPSTREAM_COMMIT_URL"
  exit 1
fi

if [ -e "$DIRECTORY_NAME" ]; then
  echo "Error: directory already exists: $DIRECTORY_NAME"
  exit 1
fi

# Make sure SSH auth to GitHub works before doing all the work.
if ! ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
  echo "Warning: SSH authentication to GitHub may not be configured."
  echo "Test it manually with:"
  echo "  ssh -T git@github.com"
  echo
  echo "Continuing anyway..."
fi

mkdir "$DIRECTORY_NAME"
cd "$DIRECTORY_NAME"

git init

# Use upstream HTTPS URL from the commit URL for fetching the source commit.
git remote add upstream "$UPSTREAM_REPO_URL"

git fetch --depth 1 upstream "$COMMIT_SHA"
git checkout FETCH_HEAD

rm -rf .git

git init
git add .
git commit -m "Initial commit"
git branch -M main

# Create the GitHub repo only if it does not already exist.
if gh repo view "$OWNER/$REPO_NAME" >/dev/null 2>&1; then
  echo "GitHub repo already exists: $OWNER/$REPO_NAME"
else
  echo "Creating GitHub repo: $OWNER/$REPO_NAME"
  gh repo create "$OWNER/$REPO_NAME" "--$VISIBILITY"
fi

# Push using SSH, not HTTPS.
git remote add origin "$NEW_GITHUB_REPO_SSH_URL"
git push -u origin main
