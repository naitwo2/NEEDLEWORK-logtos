package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"

)

func main() {
    if err := readLine("pa_2行.log"); err != nil {
        fmt.Println(os.Stderr, err)
        os.Exit(1)
    }
}

func readLine(filename string) error {
	logdataMap := map[string]string{}

    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    reader := bufio.NewReader(file)

    for {
        line, isPrefix, err := reader.ReadLine()
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
		//fmt.Print(string(line))
		
		// カンマでスライス
		slice := strings.Split(string(line), ",")

/* 		for i := 0; i < len(slice); i +=2 {
			logdataMap[i] = slice[i+1]
		} */

		i := 0
  		for _, str := range slice {
			logdataMap["hoge"] = str
			i = i + 1
		}  

		fmt.Println(logdataMap)
		//fmt.Printf(logdataMap[])

        if !isPrefix {
            fmt.Println()
        }
	}



    return nil
}