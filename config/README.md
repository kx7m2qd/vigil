Engine configs Vigil passes explicitly. Each one replaces any config the scanned
repo ships for that engine, because the repo is untrusted and those configs can
suppress findings. Do not add a `.gitleaksignore` to this folder: gitleaks reads
it via `--gitleaks-ignore-path`.
