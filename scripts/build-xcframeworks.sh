#!/bin/bash

# Script to build and create XCFrameworks from Package.swift
# Builds dynamic frameworks for all library products across multiple platforms

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

# Products to build (from Package.swift)
PRODUCTS=(
    "Reporting"
    "Filters"
    "Sinks"
    "Installations"
    "Recording"
    "DiscSpaceMonitor"
    "BootTimeMonitor"
    "DemangleFilter"
)

# Platforms to build for
PLATFORMS=(
    "iOS"
    "iOS Simulator"
    "tvOS"
    "tvOS Simulator"
    "watchOS"
    "watchOS Simulator"
    "macOS"
)

get_archs() {
    case "$1" in
        "iOS"|"tvOS")
            echo "arm64 arm64e"
            ;;
        "iOS Simulator"|"tvOS Simulator")
            echo "x86_64 arm64 arm64e"
            ;;
        "watchOS")
            echo "arm64_32"
            ;;
        "watchOS Simulator")
            echo "x86_64 arm64"
            ;;
        "macOS")
            echo "x86_64 arm64"
            ;;
        *)
            echo "arm64 arm64e"
            ;;
    esac
}

build() {
    local scheme=$1
    local platform=$2
    local archs=$(get_archs "$platform")

    echo "Building $scheme for $platform (archs: $archs)"

    # Create logs directory
    mkdir -p "$BUILD_DIR/archives/$scheme/logs"

    # Sanitize platform name for filename (replace spaces with hyphens)
    local platform_safe="${platform// /-}"
    local log_file="$BUILD_DIR/archives/$scheme/logs/${platform_safe}.log"

    local build_result=0
    DYLIB_BUILD=1 xcodebuild archive \
        -workspace "$PROJECT_ROOT" \
        -scheme "$scheme" \
        -destination "generic/platform=$platform" \
        -archivePath "$BUILD_DIR/archives/$scheme/$platform" \
        -derivedDataPath "$BUILD_DIR/.derived-data" \
        -configuration Release \
        SKIP_INSTALL=NO \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
        ARCHS="$archs" \
        > "$log_file" 2>&1 || build_result=$?

    if [ $build_result -ne 0 ] || [ ! -d "$BUILD_DIR/archives/$scheme/$platform.xcarchive" ]; then
        echo "========================================="
        echo "BUILD FAILED: $scheme for $platform"
        echo "========================================="
        echo ""
        echo "Log output:"
        echo "========================================="
        cat "$log_file"
        echo "========================================="
        exit 1
    fi
}

package() {
    local scheme=$1
    shift
    local platforms=("$@")

    local args=()

    for platform in "${platforms[@]}"; do
        local framework_path="$BUILD_DIR/archives/$scheme/$platform.xcarchive/Products/usr/local/lib/$scheme.framework"

        echo "Adding $platform to $scheme.xcframework"

        # Check if dSYM exists
        local dsym_path="$BUILD_DIR/archives/$scheme/$platform.xcarchive/dSYMs/$scheme.framework.dSYM"

        args+=("-framework" "$framework_path")

        if [ -d "$dsym_path" ]; then
            # Get absolute path for dSYM
            local abs_dsym_path=$(cd "$(dirname "$dsym_path")" && pwd)/$(basename "$dsym_path")
            args+=("-debug-symbols" "$abs_dsym_path")
        fi
    done

    mkdir -p "$BUILD_DIR/frameworks"
    echo "Creating $scheme.xcframework"
    xcodebuild -create-xcframework "${args[@]}" -output "$BUILD_DIR/frameworks/$scheme.xcframework"
}

compress_all() {
    echo "Zipping all xcframeworks into KSCrash.xcframeworks.zip"
    mkdir -p "$BUILD_DIR/artifacts"

    pushd "$BUILD_DIR/frameworks" > /dev/null
    zip -r -q "../artifacts/KSCrash.xcframeworks.zip" .
    popd > /dev/null
}

echo "========================================="
echo "KSCrash XCFramework Builder"
echo "========================================="
echo "Products to build:"
printf "  %s\n" "${PRODUCTS[@]}"
echo ""
echo "Platforms:"
printf "  %s\n" "${PLATFORMS[@]}"
echo ""

echo "xcodebuild version:"
xcodebuild -version
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "$BUILD_DIR"
echo "Clean complete"
echo ""

# Build each product for each platform
for product in "${PRODUCTS[@]}"; do
    echo "========================================="
    echo "Building product: $product"
    echo "========================================="

    for platform in "${PLATFORMS[@]}"; do
        build "$product" "$platform"
    done

    echo ""
    # Package into xcframework
    package "$product" "${PLATFORMS[@]}"

    echo ""
done

# Compress all xcframeworks into a single archive
compress_all

echo "========================================="
echo "Build Complete!"
echo "========================================="
echo "XCFrameworks: $BUILD_DIR/frameworks/"
echo "Archive: $BUILD_DIR/artifacts/KSCrash.xcframeworks.zip"
}
