{ self }:
final: prev: {
  peerix = self.packages.${prev.system}.peerix;
  peerix-full = self.packages.${prev.system}.peerix-full;
}
