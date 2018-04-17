cd "$PATHAUTOTARGETSRC"
[ -f "$VERSIONPARSEC.tar.gz" ] || run wget "http://parsec.cs.princeton.edu/download/$VERSIONPARSECURL/$VERSIONPARSEC.tar.gz"
[ -d "$VERSIONPARSEC" ] || run tar xf "$VERSIONPARSEC.tar.gz"

cd "$VERSIONPARSEC"
if [ ! -f .autosetup.patched-parsec_canneal ]; then
    run patch -p0 < "$PATHROOT/patches/parsec_canneal.patch"
    touch .autosetup.patched-parsec_canneal
fi
