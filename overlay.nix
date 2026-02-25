{ self }:
final: prev: {
  peerix = self.packages.${prev.system}.peerix;
  peerix-unwrapped = self.packages.${prev.system}.peerix-unwrapped;
  peerix-python = self.packages.${prev.system}.peerix-python;
}
