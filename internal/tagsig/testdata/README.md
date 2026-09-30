Made with throwaway keys (the private halves were discarded):

```sh
ssh-keygen -t ed25519 -N "" -f key
git -c gpg.format=ssh -c user.signingkey=key tag -s v1.0.0 -m "release v1.0.0"
git cat-file tag v1.0.0 > signed.tag
```

`git verify-tag` accepts `signed.tag` with `maintainer.pub`.
