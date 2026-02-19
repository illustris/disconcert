{
	description = "TLS certificate/DNS consistency checker";

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
		flake-utils.url = "github:numtide/flake-utils";
	};

	outputs = { self, nixpkgs, flake-utils }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				pkgs = nixpkgs.legacyPackages.${system};
			in {
				packages.default = pkgs.buildGoModule {
					pname = "disconcert";
					version = "0.1.0";
					src = ./src;
					vendorHash = null;
				};

				devShells.default = pkgs.mkShell {
					buildInputs = [ pkgs.go ];
				};
			}
		);
}
