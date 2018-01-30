package main

import (
	"fmt"

	"github.com/mailoman/go-secure/secure"
)

func main() {
	enc := secure.NewHashids()
	encoded, _ := enc.SetKey("01234567891011121314151617181920").Encrypt("/myapi/test")
	fmt.Println(encoded)
}
// R2bIzrfeXTPDUr7UJViP9I5VU2ECJwTe7