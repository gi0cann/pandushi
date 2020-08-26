package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	fmt.Println("gscanner")
	fd, err := os.Open("github_get.req")
	if err != nil {
		panic(err)
	}

	text, err := ioutil.ReadAll(fd)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", text)

}
