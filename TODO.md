# Peerix TODO

## NixOS Module Enhancements

- [x] Add priority customization option (`services.peerix.priority`)
- [x] Add IPFS options as part of peerix module (`services.peerix.ipfs.*`)
  - IPFS mode + default options enabled by default
  - Option to disable (`services.peerix.ipfs.enable = false`)
- [x] Add manual cache update trigger / peerix restart mechanism
  - Use `systemctl reload peerix` to trigger store rescan
  - Sends SIGHUP to trigger scan_and_publish + CID sync
