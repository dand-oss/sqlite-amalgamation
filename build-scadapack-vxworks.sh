#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
UNAME_S=$(uname -s)

if [[ "$UNAME_S" == MSYS* || "$UNAME_S" == MINGW* || "$UNAME_S" == CYGWIN* ]]; then
    DEFAULT_FIRMWARE_ROOT=/i/src/wt-scadapack-datalogger/scadapack/firmware
    DEFAULT_CTOOLS_ROOT=/i/t/scadapack/ctools
    DEFAULT_TOOLCHAIN=ScadaPack350CtoolsToolchain.cmake
    DEFAULT_BUILD_DIR="$ROOT/build/scadapack-vxworks-ctools"
else
    DEFAULT_FIRMWARE_ROOT=/home/appsmith/asv/src/wt-scadapack-datalogger/scadapack/firmware
    DEFAULT_CTOOLS_ROOT=
    DEFAULT_TOOLCHAIN=ScadaPack350Toolchain.cmake
    DEFAULT_BUILD_DIR="$ROOT/build/scadapack-vxworks"
fi

FIRMWARE_ROOT=${SCADAPACK_FIRMWARE_ROOT:-"$DEFAULT_FIRMWARE_ROOT"}
BUILD_DIR=${SCADAPACK_SQLITE_BUILD_DIR:-"$DEFAULT_BUILD_DIR"}
INSTALL_PREFIX=${SCADAPACK_SQLITE_PREFIX:-/i/ports/install/sqlite3/scadapack-vxworks}
CTOOLS_ROOT=${SCADAPACK_CTOOLS:-"$DEFAULT_CTOOLS_ROOT"}
GENERATOR=${CMAKE_GENERATOR:-Ninja}

if [ ! -f "$FIRMWARE_ROOT/cmake/ScadaPack350Toolchain.cmake" ]; then
    echo "Missing SCADAPack firmware root: $FIRMWARE_ROOT" >&2
    echo "Set SCADAPACK_FIRMWARE_ROOT to the scadapack/firmware directory." >&2
    exit 1
fi

if [ -z "$CTOOLS_ROOT" ]; then
    CTOOLS_ROOT="$FIRMWARE_ROOT/../third_party/scadapack-300-c++-tools-1.61"
fi

if [ ! -e "$CTOOLS_ROOT/Controller/TelePACE/CTOOLS.H" ]; then
    CTOOLS_ROOT="$FIRMWARE_ROOT/third_party/ctools"
fi

CONFIGURE_ARGS=(
    -S "$ROOT"
    -B "$BUILD_DIR"
    -G "$GENERATOR"
    -DCMAKE_TOOLCHAIN_FILE="$FIRMWARE_ROOT/cmake/$DEFAULT_TOOLCHAIN"
    -DCMAKE_BUILD_TYPE=Release
    -DSQLITE_ENABLE_VXWORKS=ON
    -DBUILD_SHELL=OFF
    -DSCADAPACK_CTOOLS="$CTOOLS_ROOT"
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
)

BUILD_ARGS=(
    --build "$BUILD_DIR"
)

INSTALL_ARGS=(
    --install "$BUILD_DIR"
)

cmake "${CONFIGURE_ARGS[@]}"
cmake "${BUILD_ARGS[@]}"
cmake "${INSTALL_ARGS[@]}"

echo "Installed SCADAPack VxWorks SQLite package to: $INSTALL_PREFIX"
