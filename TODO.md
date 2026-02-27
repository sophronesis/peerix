# Peerix TODO

## NixOS Module Enhancements

- [x] Add priority customization option (`services.peerix.priority`)
- [x] Add IPFS options as part of peerix module (`services.peerix.ipfs.*`)
  - IPFS mode + default options enabled by default
  - Option to disable (`services.peerix.ipfs.enable = false`)
- [x] Add manual cache update trigger / peerix restart mechanism
  - Use `systemctl reload peerix` to trigger store rescan
  - Sends SIGHUP to trigger scan_and_publish + CID sync

## Dashboard / HTTP API

- [ ] Add pause scan option from dashboard

## Code Cleanup

- [x] Remove WAN, both, libp2p, hybrid modes - keep only lan and ipfs
  - Deleted: wan.py, libp2p_host.py, libp2p_dht.py, libp2p_store.py, libp2p_protocols.py
  - Deleted: ipfs_compat.py, peer_identity.py, net_validation.py
  - Deleted: nix/libp2p.nix
  - Simplified: app.py, __main__.py, module.nix, flake.nix, overlay.nix, tracker_client.py
