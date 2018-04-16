if [ -f "$PATHSPEC/shrc" ]; then
	echo "using existing SPEC CPU2006 installation"
	cd "$PATHSPEC"
	if [ ! -f .autosetup.patched-dealII-stddef ]; then
	    run patch -p0 < "$PATHROOT/patches/SPEC-CPU2006-dealII-stddef.patch"
	    touch .autosetup.patched-dealII-stddef
	fi
	if [ ! -f .autosetup.patched-gcc-lazysan ]; then
	    run patch -p0 < "$PATHROOT/patches/SPEC-CPU2006-gcc-lazysan.patch"
	    touch .autosetup.patched-gcc-lazysan
	fi
else
	echo "please set \$PATHSPEC to the root of your SPEC CPU2006 installation" >&2
fi
