source "$PATHROOT/autosetup/passes/helper/reset.inc"
source "$PATHROOT/autosetup/passes/helper/lto.inc"

# tcmalloc settings
CONFIG_MALLOC=tcmalloc-metalloc
CONFIG_FIXEDCOMPRESSION=false
CONFIG_METADATABYTES=8
CONFIG_DEEPMETADATA=false
CONFIG_DEEPMETADATABYTES=128
CONFIG_SAFESTACK_OPTIONS="largestack=true"
CONFIG_ALLOC_SIZE_HOOK=dang_alloc_size_hook

# passes
add_lto_args -lazy-san

ldflagsnolib="$ldflagsnolib -L$PATHAUTOFRAMEWORKOBJ/staticlib-$instance"
ldflagsnolib="$ldflagsnolib -Wl,-whole-archive,-l:libmetadata.a,-no-whole-archive"

source "$PATHROOT/autosetup/passes/helper/tcmalloc.inc"
