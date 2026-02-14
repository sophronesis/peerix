# Custom derivation that takes ~1 minute to build
# Used to test peerix WAN cache sharing (build on one peer, serve to other)
let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/2343bbb58f99267223bc2aac4fc9ea301a155a16.tar.gz";
    sha256 = "03qwpi78578vlp1y1wfg5yrfyinp82sq16z910gijpphc16dd2rf";
  };
  pkgs = import nixpkgs { system = "x86_64-linux"; };
in
pkgs.stdenv.mkDerivation {
  pname = "peerix-slow-test";
  version = "1.1";

  # No source needed
  dontUnpack = true;

  buildPhase = ''
    echo "Starting slow deterministic build..."
    # Generate a large deterministic dataset by hashing in a loop
    val="peerix-test-seed"
    for i in $(seq 1 500); do
      val=$(echo -n "$val" | sha256sum | cut -d' ' -f1)
      if [ $((i % 100)) -eq 0 ]; then
        echo "Progress: $i / 500 iterations (val=$val)"
      fi
    done
    echo "Final hash: $val"
    echo "$val" > result.txt
  '';

  installPhase = ''
    mkdir -p $out
    cp result.txt $out/
    echo "Build completed successfully" > $out/status.txt
  '';
}
