# Contributing

## Workflow

- Do not commit directly to `main`.
- Create a short-lived branch for every change.
- Open a pull request into `main`.
- Merge only after CI is green.

Branch naming:
- `feat/<short-topic>`
- `fix/<short-topic>`
- `chore/<short-topic>`
- `docs/<short-topic>`

## Local Steps

1. Sync latest `main`:

```bash
git checkout main
git pull --ff-only
```

2. Create a feature branch:

```bash
git checkout -b feat/<short-topic>
```

3. Run tests before pushing:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -q
```

4. Push your branch and open a PR.

## Pull Request Guidelines

- Keep PRs focused and small.
- Add or update tests for behavior changes.
- Update docs (`README.md`, `CHANGELOG.md`, `SECURITY.md`) when relevant.
- Use clear commit messages:
  - `feat: ...`
  - `fix: ...`
  - `test: ...`
  - `ci: ...`
  - `chore: ...`

## Recommended GitHub Branch Protection for `main`

Configure these in repository settings:

- Require a pull request before merging.
- Require status checks to pass before merging.
  - include the CI workflow checks.
- Restrict who can push to matching branches.
- Do not allow force pushes.
- Do not allow branch deletion.
