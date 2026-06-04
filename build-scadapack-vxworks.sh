#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FIRMWARE_ROOT=${SCADAPACK_FIRMWARE_ROOT:-/home/appsmith/asv/src/wt-scadapack-datalogger/scadapack/firmware}
BUILD_DIR=${SCADAPACK_SQLITE_BUILD_DIR:-"$ROOT/build/scadapack-vxworks"}
INSTALL_PREFIX=${SCADAPACK_SQLITE_PREFIX:-/i/ports/install/sqlite3/scadapack-vxworks}
CTOOLS_ROOT=${SCADAPACK_CTOOLS:-"$FIRMWARE_ROOT/../third_party/scadapack-300-c++-tools-1.61"}

if [ ! -f "$FIRMWARE_ROOT/cmake/ScadaPack350Toolchain.cmake" ]; then
    echo "Missing SCADAPack firmware root: $FIRMWARE_ROOT" >&2
    echo "Set SCADAPACK_FIRMWARE_ROOT to the scadapack/firmware directory." >&2
    exit 1
fi

if [ ! -e "$CTOOLS_ROOT/Controller/TelePACE/CTOOLS.H" ]; then
    CTOOLS_ROOT="$FIRMWARE_ROOT/third_party/ctools"
fi

CONFIGURE_ARGS=(
    -S "$ROOT"
    -B "$BUILD_DIR"
    -DCMAKE_TOOLCHAIN_FILE="$FIRMWARE_ROOT/cmake/ScadaPack350Toolchain.cmake"
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
