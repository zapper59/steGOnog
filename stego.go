package main

import (
  "flag"
  "fmt"
  "log"
  "os"
  gse "./github.com/johnprather/go-string-encrypt"
  "crypto/sha256"
  "encoding/base64"
  "math/big"
  "io/ioutil"
  "strings"
  "runtime/debug"
)

const offset = 64
const streamEnd_str = "1111111111111110"
var streamEnd = []byte{0xFF, 0xFE}
var numbytes = 3

func main() {
  dec := flag.Bool("d", false, "Set to decrypt mode, off by default")
  flag.Parse()
  if *dec {
    decrypt()
  } else {
    encrypt()
  }
}

func encrypt() {
  args := flag.Args() // Args: input-file password output-file message
  if len(args) != 4 {
    argError()
  }

  fmt.Println("Beginning encryption....")

  img := readImage(args[0])

  // Get cyphertext
  _ct, e := gse.Encrypt(getKey(args[1]), args[3])
  checkerr(e)
  _ct_b, e := base64.StdEncoding.DecodeString(_ct)
  checkerr(e)
  _ct_b = append(_ct_b, streamEnd...)
  ct := new(big.Int).SetBytes(_ct_b).Text(2)  // Binary representation of cyphertext

  currat := offset
  for _, val := range ct {
    if currat >= len(img){
      log.Fatal("Image too small")
    }
    if val == '0' {
      img[currat][numbytes-1] &= 0xFE
    } else if val == '1' {
      img[currat][numbytes-1] |= 1
    } else {
      log.Fatalf("Value %d invalid\n", val)
    }
    currat++
  }

  writeImage(args[2], img)
  fmt.Printf("Wrote output to %s\n", args[2])
}

func decrypt() {
  args := flag.Args() // Args: input-file password output-file message
  if len(args) != 2 {
    argError()
  }

  fmt.Println("Beginning decryption....")

  img := readImage(args[0])

  // Read cyphertext
  found := false
  ct := ""
  for _, val := range img[offset:] {
    if val[numbytes-1] & 1 == 0 {
      ct += "0"
    } else {
      ct += "1"
    }
    if (strings.HasSuffix(ct, streamEnd_str)) {
      found = true
      break
    }
  }
  if !found {
    log.Fatalf("Cyphertext not found.\n")
  }

  // Decrypt message
  if _ct_b, good := new(big.Int).SetString(ct, 2); !good {
    log.Fatalf("Message could not be decrypted.\n")
  } else {
    _ct := _ct_b.Bytes()
    _ct = _ct[:len(_ct) - len(streamEnd)]
    based := base64.StdEncoding.EncodeToString(_ct)
    msg, e := gse.Decrypt(getKey(args[1]), based)
    checkerr(e)
    fmt.Println("Found message is: ", msg)
  }
}

func readImage(file string) (ret [][]byte) {
  f, e := ioutil.ReadFile(file)
  checkerr(e)
  ret = make([][]byte, len(f)/3)
  for i:=0; i < len(ret); i++ {
    ret[i] = f[i*numbytes : (i+1) * numbytes]
  }
  return
}

func writeImage(file string, data [][]byte) {
  buff := []byte{}
  for _, a := range data {
    buff = append(buff, a...)
  }

  e := ioutil.WriteFile(file, buff, os.ModePerm)
  checkerr(e)
}


func getKey(pass string) string {
  sum := sha256.Sum256([]byte(pass))
  return base64.StdEncoding.EncodeToString(sum[:])
}

func checkerr(err error) {
  if err != nil {
    debug.PrintStack()
    log.Fatal(err)
  }
}

func argError() {
  fmt.Printf("Usage: %s [-d] input-file password [output-file] [message]\n" +
     "Note: output-file/message only used when -d defined\n", os.Args[0])
  flag.PrintDefaults()
  log.Fatalf("Invalid args.  Exiting\n")
}
