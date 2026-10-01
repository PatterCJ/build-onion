A real lockfile with a dependency that runs an install script (esbuild), made
without running any scripts:

```sh
npm install --package-lock-only --ignore-scripts esbuild@0.24.0 semver@7.6.3
```
