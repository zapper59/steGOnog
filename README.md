# SteGoNog
Does simple steganography on .bmp files through a command line interface.

## Compilation
go build -o stegonog

## Encryption
```
./stegonog input-file password output-file message
```

## Decryption
```
./stegonog -d input-file password
```

## Example
```
./stegonog cat4.bmp "yolo" out.bmp "yolala"

./stegonog -d out.bmp "yolo"
```

