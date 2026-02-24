{ self }:
final: prev: {
  peerix = self.packages.${prev.system}.peerix;
  peerix-full = self.packages.${prev.system}.peerix-full;
  peerix-unwrapped = self.packages.${prev.system}.peerix-unwrapped;
  peerix-full-unwrapped = self.packages.${prev.system}.peerix-full-unwrapped;
  peerix-python = self.packages.${prev.system}.peerix-python;
}
