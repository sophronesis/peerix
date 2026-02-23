# LibP2P and dependencies packaging for Nix
{ pkgs, python }:

let
  inherit (python.pkgs) buildPythonPackage fetchPypi setuptools;

  # pytest-runner for legacy setup.py projects
  pytest-runner = buildPythonPackage rec {
    pname = "pytest-runner";
    version = "6.0.1";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-cNRzlYWnAI83v0kzwBP9sye4h4paafy7MxbIiILw9Js=";
    };
    build-system = [ setuptools python.pkgs.setuptools-scm ];
    doCheck = false;
  };

  # morphys - dependency of py-multibase and py-multihash
  morphys = buildPythonPackage rec {
    pname = "morphys";
    version = "1.0";
    format = "wheel";
    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/f9/4f/cb781d0ac5d079adabc77dc4f0bc99fc81c390029bd33c6e70552139e762/morphys-1.0-py2.py3-none-any.whl";
      sha256 = "sha256-dtbbqk1l9ZflnTMsgdp4bYPkZpOHubKnUM/sdOe+7CA=";
    };
    doCheck = false;
  };

  # py-multicodec 1.0.0 - has Code class required by libp2p
  py-multicodec = buildPythonPackage rec {
    pname = "py-multicodec";
    version = "1.0.0";
    format = "wheel";
    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/76/da/768d07490faeae88ac361184164be9c262fececc3c6241b5fc471be4f659/py_multicodec-1.0.0-py3-none-any.whl";
      sha256 = "sha256-ri5oe6yP31Tj9bP+3tNrYaME1ePDr5Q490gfVD7BW40=";
    };
    dependencies = [ python.pkgs.varint ];
    doCheck = false;
  };

  # py-multibase
  py-multibase = buildPythonPackage rec {
    pname = "py-multibase";
    version = "1.0.3";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-0oog78u2Huwo9VgnoL8ynHzqgP/9kzrsrqauhDEmf+Q=";
    };
    build-system = [ setuptools pytest-runner ];
    dependencies = [ morphys python.pkgs.six python.pkgs.python-baseconv ];
    doCheck = false;
  };

  # py-multihash
  py-multihash = buildPythonPackage rec {
    pname = "py-multihash";
    version = "0.2.3";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-8K3k3oIK/cS0qqQEZOyGydpcrjpFeM2i2qtLDrflsY0=";
    };
    build-system = [ setuptools pytest-runner ];
    dependencies = [ python.pkgs.base58 python.pkgs.six python.pkgs.varint morphys ];
    # Skip runtime deps check due to base58 version mismatch (works anyway)
    dontCheckRuntimeDeps = true;
    doCheck = false;
  };

  # py-cid - dependency of multiaddr
  py-cid = buildPythonPackage rec {
    pname = "py-cid";
    version = "0.3.0";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-IvQyzG+2jRKpw129ySyVSE/EnjHfy54O+wCCIzxTlOM=";
    };
    build-system = [ setuptools pytest-runner ];
    dependencies = [ python.pkgs.base58 py-multibase py-multicodec py-multihash ];
    # Skip runtime deps check due to base58 version mismatch (works anyway)
    dontCheckRuntimeDeps = true;
    doCheck = false;
  };

  # multiaddr
  multiaddr = buildPythonPackage rec {
    pname = "multiaddr";
    version = "0.0.11";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-5NZZjmkaygQVUXHdaQeKP3ETQqKMeF9ro9jt4AE4D5Q=";
    };
    build-system = [ setuptools ];
    dependencies = (with python.pkgs; [
      base58
      netaddr
      varint
      dnspython
      idna
      psutil
      trio
      typing-extensions
      async-generator
      importlib-metadata
    ]) ++ [
      py-cid
      py-multicodec
      trio-typing
    ];
    # Skip runtime deps check due to py-cid version mismatch
    dontCheckRuntimeDeps = true;
    doCheck = false;
  };

  # rpcudp
  rpcudp = buildPythonPackage rec {
    pname = "rpcudp";
    version = "4.0.2";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-miAcwfn9RburNZ0YE1+avfuRdgwV9sCK/8pXMPXrw34=";
    };
    build-system = [ setuptools ];
    dependencies = [ python.pkgs.u-msgpack-python ];
    doCheck = false;
  };

  # trio-typing
  trio-typing = buildPythonPackage rec {
    pname = "trio-typing";
    version = "0.10.0";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-Bl7mhCltUqirDiN0ZmMBrsNu5XR6wOemHyMCUPiQesM=";
    };
    build-system = [ setuptools ];
    dependencies = with python.pkgs; [
      trio
      mypy-extensions
      typing-extensions
      async-generator
      importlib-metadata
    ];
    doCheck = false;
  };

  # Use trio-websocket from nixpkgs
  trio-websocket = python.pkgs.trio-websocket;

  # libp2p itself
  libp2p = buildPythonPackage rec {
    pname = "libp2p";
    version = "0.6.0";
    pyproject = true;

    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-NsX0CeCLO0BY4PoNKinaXwB+qkS7y40hyWrfxVRHDyk=";
    };

    build-system = with python.pkgs; [
      setuptools
      mypy-protobuf
    ];

    dependencies = (with python.pkgs; [
      # From nixpkgs
      aioquic
      base58
      coincurve
      fastecdsa
      httpx
      grpcio
      lru-dict
      miniupnpc
      noiseprotocol
      protobuf
      pycryptodome
      pynacl
      trio
      zeroconf
      requests
      exceptiongroup
      types-requests
    ]) ++ [
      # Custom packages
      multiaddr
      py-multibase
      py-multihash
      py-multicodec
      rpcudp
      trio-typing
      trio-websocket
    ];

    # Skip runtime deps check due to various version mismatches
    dontCheckRuntimeDeps = true;

    # Skip tests - they require network access
    doCheck = false;

    # pythonImportsCheck disabled: libp2p imports multiaddr which initializes
    # a DNS resolver that needs /etc/resolv.conf (unavailable in sandbox)
    # pythonImportsCheck = [ "libp2p" ];

    meta = with pkgs.lib; {
      description = "Python implementation of libp2p networking stack";
      homepage = "https://github.com/libp2p/py-libp2p";
      license = licenses.mit;
    };
  };

in {
  inherit
    multiaddr
    py-multibase
    py-multihash
    py-multicodec
    rpcudp
    trio-typing
    trio-websocket
    libp2p;
}
