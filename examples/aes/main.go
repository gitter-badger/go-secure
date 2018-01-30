package main

import (
	"fmt"

	"github.com/mailoman/go-secure/secure"
)

func main() {
	enc := secure.NewAes()
	encoded, _ := enc.SetKey("01234567891011121314151617181920").Encrypt("/myapi/test")
	fmt.Println(encoded)
}
// 116A47bJD9FTpS3BmHSsA8bhjZIUQsiNrWyC