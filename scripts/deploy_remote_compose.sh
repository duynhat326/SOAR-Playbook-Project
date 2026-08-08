#!/usr/bin/env bash

set -euo pipefail

: "${DEPLOY_HOST:?DEPLOY_HOST is required}"
: "${DEPLOY_USER:?DEPLOY_USER is required}"
: "${DEPLOY_PATH:?DEPLOY_PATH is required}"
: "${DEPLOY_SSH_KEY:?DEPLOY_SSH_KEY is required}"
: "${SOAR_DEPLOY_ENV_FILE:?SOAR_DEPLOY_ENV_FILE is required}"
: "${SOAR_IMAGE_NAMESPACE:?SOAR_IMAGE_NAMESPACE is required}"
: "${SOAR_IMAGE_TAG:?SOAR_IMAGE_TAG is required}"

GHCR_USERNAME="${GHCR_USERNAME:-}"
GHCR_READ_TOKEN="${GHCR_READ_TOKEN:-}"
SOAR_ENVIRONMENT_NAME="${SOAR_ENVIRONMENT_NAME:-staging}"
DEPLOY_WITH_POSTGRES="${DEPLOY_WITH_POSTGRES:-false}"
RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS:-true}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
tmp_dir="$(mktemp -d)"
key_file="${tmp_dir}/deploy.key"
env_file="${tmp_dir}/deploy.env"

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

printf '%s\n' "${DEPLOY_SSH_KEY}" > "${key_file}"
chmod 600 "${key_file}"
printf '%s\n' "${SOAR_DEPLOY_ENV_FILE}" > "${env_file}"

compose_files=("${repo_root}/docker-compose.release.yml")
remote_files=("docker-compose.release.yml")
compose_flags=(-f docker-compose.release.yml)
profile_flags=()

if [[ "${DEPLOY_WITH_POSTGRES}" == "true" ]]; then
  compose_files+=("${repo_root}/docker-compose.release.postgres.yml")
  remote_files+=("docker-compose.release.postgres.yml")
  compose_flags+=(-f docker-compose.release.postgres.yml)
  profile_flags+=(--profile postgres)
fi

ssh_opts=(
  -i "${key_file}"
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
)

ssh "${ssh_opts[@]}" "${DEPLOY_USER}@${DEPLOY_HOST}" "mkdir -p '${DEPLOY_PATH}'"

for index in "${!compose_files[@]}"; do
  scp "${ssh_opts[@]}" "${compose_files[index]}" "${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/${remote_files[index]}"
done

scp "${ssh_opts[@]}" "${env_file}" "${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/deploy.env"

export REMOTE_DEPLOY_PATH="${DEPLOY_PATH}"
export REMOTE_GHCR_USERNAME="${GHCR_USERNAME}"
export REMOTE_GHCR_READ_TOKEN="${GHCR_READ_TOKEN}"
export REMOTE_RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS}"
export REMOTE_SOAR_ENVIRONMENT_NAME="${SOAR_ENVIRONMENT_NAME}"
export REMOTE_SOAR_IMAGE_TAG="${SOAR_IMAGE_TAG}"
export REMOTE_COMPOSE_FLAGS="${compose_flags[*]}"
export REMOTE_PROFILE_FLAGS="${profile_flags[*]}"

ssh "${ssh_opts[@]}" "${DEPLOY_USER}@${DEPLOY_HOST}" 'bash -s' <<'EOF'
set -euo pipefail

cd "${REMOTE_DEPLOY_PATH}"

if [[ -n "${REMOTE_GHCR_USERNAME}" && -n "${REMOTE_GHCR_READ_TOKEN}" ]]; then
  printf "%s" "${REMOTE_GHCR_READ_TOKEN}" | docker login ghcr.io -u "${REMOTE_GHCR_USERNAME}" --password-stdin
fi

read -r -a compose_flags <<<"${REMOTE_COMPOSE_FLAGS}"
read -r -a profile_flags <<<"${REMOTE_PROFILE_FLAGS}"

docker compose "${compose_flags[@]}" --env-file deploy.env "${profile_flags[@]}" pull

if [[ "${REMOTE_RUN_DB_MIGRATIONS}" == "true" ]]; then
  docker compose "${compose_flags[@]}" --env-file deploy.env "${profile_flags[@]}" --profile ops run --rm migrate
fi

docker compose "${compose_flags[@]}" --env-file deploy.env "${profile_flags[@]}" up -d --remove-orphans

printf "Deployment completed for %s using image tag %s.\n" "${REMOTE_SOAR_ENVIRONMENT_NAME}" "${REMOTE_SOAR_IMAGE_TAG}"
EOF
