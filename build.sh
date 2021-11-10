#!/bin/bash

#
# NOTE: while this build non-system seems flawed, the reason for doing this is
# that our target platform is a static wasm blob. Getting libraries with
# varying build systems to create a single wasm blob is worse than this.
#

VERSION="0.1.0"

FVERSION="${VERSION//./-}"
NATIVE_PLATFORM="`uname -s`-`uname -m`"
NATIVE_PLATFORM="`echo $NATIVE_PLATFORM | tr '[:upper:]' '[:lower:]'`"
NATIVE_DST="build/$NATIVE_PLATFORM"
NATIVE_TAR="apbpatch_$NATIVE_PLATFORM_$FVERSION.tar.gz"
WASM_DST="build/html"
WASM_ZIP="apbpatch_wasm_$FVERSION.zip"

XZ_DEFINES="-DHAVE_STDINT_H -DHAVE_STDBOOL_H -DHAVE_SMALL -DHAVE_CHECK_CRC32 -DHAVE_CHECK_CRC64 -DHAVE_ENCODERS -DHAVE_DECODER_LZMA1 -DHAVE_DECODER_LZMA2"
XZ_CFLAGS="$XZ_DEFINES -Isubprojects/xz/src/liblzma/api -Isubprojects/xz/src/liblzma/lzma -Isubprojects/xz/src/liblzma/simple -Isubprojects/xz/src/liblzma/delta -Isubprojects/xz/src/liblzma/lz -Isubprojects/xz/src/liblzma/common -Isubprojects/xz/src/common -Isubprojects/xz/src/liblzma/check -Isubprojects/xz/src/liblzma/rangecoder"
XZ_SRC="subprojects/xz/src/liblzma/lzma/lzma_decoder.c subprojects/xz/src/liblzma/lz/lz_decoder.c subprojects/xz/src/liblzma/common/common.c subprojects/xz/src/liblzma/common/stream_decoder.c subprojects/xz/src/liblzma/common/index_hash.c subprojects/xz/src/liblzma/common/stream_flags_common.c subprojects/xz/src/liblzma/common/vli_decoder.c subprojects/xz/src/liblzma/common/stream_flags_decoder.c subprojects/xz/src/liblzma/check/check.c subprojects/xz/src/liblzma/common/block_header_decoder.c subprojects/xz/src/liblzma/common/block_util.c subprojects/xz/src/liblzma/common/filter_decoder.c subprojects/xz/src/liblzma/common/block_decoder.c subprojects/xz/src/liblzma/common/vli_size.c subprojects/xz/src/liblzma/common/filter_flags_decoder.c subprojects/xz/src/liblzma/common/filter_common.c subprojects/xz/src/liblzma/check/crc32_small.c subprojects/xz/src/liblzma/check/crc64_small.c subprojects/xz/src/liblzma/lzma/lzma2_decoder.c"

YAML_DEFINES="-DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2 -DYAML_VERSION_PATCH=5 -DYAML_VERSION_STRING=\"0.2.5\""
YAML_CFLAGS="$YAML_DEFINES -I subprojects/libyaml/include"
YAML_SRC="subprojects/libyaml/src/*.c"

BZ2_DEFINES=""
BZ2_CFLAGS="$BZ2_DEFINES -Isubprojects/bzip2"
BZ2_SRC="subprojects/bzip2/bzlib.c subprojects/bzip2/decompress.c subprojects/bzip2/randtable.c subprojects/bzip2/crctable.c subprojects/bzip2/huffman.c"

MD5_CFLAGS="-Isubprojects/md5"
MD5_SRC="subprojects/md5/md5.c"

# store working directory
OLD_PWD=`pwd`

# clean up
rm -rf --one-filesystem "$NATIVE_DST"
rm -rf --one-filesystem "$WASM_DST"
rm -rf --one-filesystem build/util

# build native
#CFLAGS="-g"
CFLAGS="-Os -flto=4 -ffunction-sections -fdata-sections -Wl,--gc-sections -s"
mkdir -p "$NATIVE_DST"
gcc -o "$NATIVE_DST/apbpatch" src/main.c $CFLAGS $XZ_CFLAGS $XZ_SRC $YAML_CFLAGS $YAML_SRC $BZ2_CFLAGS $BZ2_SRC $MD5_CFLAGS $MD5_SRC
cp README.md LICENSE "$NATIVE_DST/"
cd "$NATIVE_DST"
rm -f "../$NATIVE_TAR"
tar -acjvf "../$NATIVE_TAR" *
cd "$OLD_PWD"

# build WASM
CFLAGS="-Oz"
EMFLAGS="-s ENVIRONMENT=web -s WASM=1 -s EXPORTED_FUNCTIONS=_info,_patch --shell-file ui/shell.html -s EXPORTED_RUNTIME_METHODS=cwrap -s ALLOW_MEMORY_GROWTH=1"
mkdir -p "$WASM_DST"
emcc -o "$WASM_DST/apbpatch.html" src/main.c $CFLAGS $EMFLAGS $XZ_CFLAGS $XZ_SRC $YAML_CFLAGS $YAML_SRC $BZ2_CFLAGS $BZ2_SRC $MD5_CFLAGS $MD5_SRC
# pre-compress
brotli -k -f -q 11 "$WASM_DST/apbpatch.wasm" "$WASM_DST/apbpatch.js"
gzip -k -f -9 "$WASM_DST/apbpatch.wasm" "$WASM_DST/apbpatch.js"
# rename html to index
mv "$WASM_DST/apbpatch.html" "$WASM_DST/index.html"
# include helpers
mkdir "build/util"
cp util/htaccess "$WASM_DST/.htaccess"
cp util/serve.py "build/util/serve.py"
# zip it up
cd build
rm -f "$WASM_ZIP"
7z -mx=9 a "$WASM_ZIP" html util ../README.md ../LICENSE
cd "$OLD_PWD"
