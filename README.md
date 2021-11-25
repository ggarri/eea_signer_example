## Requirements
- Go version >= 1.16

# How to run

## 1. Download vendors
```bash
go mod vendor
```

## 2. Compile Go binary
```bash
go build -o ./build/eea_signer
```

## 3. Execute Go Binary
```bash
./build/eea_signer
```

...expected output
```
2021/11/25 07:00:05 Public address of signer:	 0xF9aa3260D7c64a4E5190EE7709fb90b79620d8a9
2021/11/25 07:00:05 Signed TxData (Zero Gas Gas):	 0xf8cf80808094000000000000000000000000a1b2c3d4e5f678908080821419a0f65c9bf4b9bf2332db5de3fae26ba44ec04f2ff8e347e86a3687770f96f2a481a05d3b917d49600338951429d139f2b188d2251572c1338392e771bf9df24a616aa00542de47c272516862bae08c53f1cb034439a739184fe707208dd92817b2dc1af842a041f783032b3d30f0ecd971c4c6d73ce232861f1660fda8f9d834e1d2fb40dd77a00542de47c272516862bae08c53f1cb034439a739184fe707208dd92817b2dc1a8a72657374726963746564
2021/11/25 07:00:05 Signed TxData (Non-Zero Gas):	 0xf8d28080830dbba094000000000000000000000000a1b2c3d4e5f67890808082141aa0b33708b3850381295c0facbf3dff8c8834e4a15d39bac1fa735c0bb41cc0d8e8a055ab2218374b0cfbc0b9e6fc6d14d18c1fdde9ddadf73e528bd09bb056c8fc64a00542de47c272516862bae08c53f1cb034439a739184fe707208dd92817b2dc1af842a041f783032b3d30f0ecd971c4c6d73ce232861f1660fda8f9d834e1d2fb40dd77a00542de47c272516862bae08c53f1cb034439a739184fe707208dd92817b2dc1a8a72657374726963746564
2021/11/25 07:00:05 execution completed
```


