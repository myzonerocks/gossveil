{
  mkShell,
  lib,
  stdenv,
  bun,
  jdk21,
  git,
  curl,
  jq,
  xz,
  unzip,
  alejandra,
}:
mkShell {
  name = "gossveil";
  packages = [
    # The web package builds and tests with bun; the Kotlin package needs a JDK for Gradle.
    bun
    jdk21
    git
    curl
    jq
    xz
    unzip
    alejandra
  ];

  # The Zig compiler is pinned in .zigversion and installed by tools/toolchain-sync into
  # .local/zig, so every host builds with the same one whatever nixpkgs carries.
  shellHook =
    ''
      export PATH="$PWD/.local/zig/current:$PATH"
      [ -x "$PWD/.local/zig/current/zig" ] || echo "run tools/toolchain-sync to install the pinned Zig"
    ''
    + lib.optionalString stdenv.hostPlatform.isDarwin ''
      # Xcode's clang and SDK stay the C toolchain on a Mac, as they are outside the shell.
      unset SDKROOT DEVELOPER_DIR NIX_CC NIX_CFLAGS_COMPILE NIX_LDFLAGS LD CC CXX CFLAGS CPPFLAGS LDFLAGS
    '';
}
