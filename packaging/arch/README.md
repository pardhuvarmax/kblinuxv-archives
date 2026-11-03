# packaging/arch

`PKGBUILD` builds `kblva` from this checkout (it reads the source from two directories up, so there is nothing to download) and installs `/usr/bin/kblva`, shell completions for bash, zsh and fish, man pages, and the docs.

```
cd packaging/arch
makepkg -f                      # build kblva-<version>-1-x86_64.pkg.tar.zst
sudo pacman -U kblva-*.pkg.tar.zst
kblva config set-root /path/to/this/repository   # once, so kblva runs from any directory
```

`makepkg -s` installs the `go` build dependency for you. The version is `0.1.0.r<commit count>.g<hash>`, taken from git. Upgrade by rebuilding after pulling, and `pacman -U` again. Remove with `sudo pacman -R kblva`.

Build products (`src/`, `pkg/`, `*.pkg.tar.zst`) are git-ignored.
