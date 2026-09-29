# Packages the binary the hermetic build step already produced. Nothing is
# compiled here, and the base is pinned by digest (`onion validate` enforces it).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY dist/onion /onion
ENTRYPOINT ["/onion"]
