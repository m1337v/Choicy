#!/bin/sh

set -eu

SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun --sdk iphoneos --find clang)"
CFLAGS="-isysroot $SDKROOT -miphoneos-version-min=8.0"

generate() {
	arch="$1"
	output="$2"
	shift 2
	if "$CLANG" $CFLAGS -S -arch "$arch" gen.c -o "$output" "$@"; then
		return 0
	fi

	rm -f "$output"
	echo "warning: failed to generate $output for $arch, skipping" >&2
	return 1
}

generate arm64 gen.arm64.s
generate arm64e gen.arm64e.s -fno-ptrauth-abi-version
generate armv7 gen.armv7.s || true
