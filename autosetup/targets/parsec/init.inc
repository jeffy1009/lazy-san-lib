cd "$PATHAUTOTARGETSRC"
[ -f "$VERSIONPARSEC.tar.gz" ] || run wget "http://parsec.cs.princeton.edu/download/$VERSIONPARSECURL/$VERSIONPARSEC.tar.gz"
[ -d "$VERSIONPARSEC" ] || run tar xf "$VERSIONPARSEC.tar.gz"

if [ ! -f .autosetup.patched-parsec_canneal ]; then
    cd "$PATHAUTOTARGETSRC/$VERSIONPARSEC/pkgs/kernels/canneal/src"
    run patch -p1 < "$PATHROOT/patches/parsec_canneal.patch"
    touch .autosetup.patched-parsec_canneal
fi
