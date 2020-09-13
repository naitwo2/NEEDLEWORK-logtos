package main

import (
    "encoding/csv"
    "fmt"
    "io"
    "os"    
)

func userCsvNewReader(fileName string) {
    fp, err := os.Open(fileName)
    if err != nil {
        panic(err)
    }
    defer fp.Close()

    reader := csv.NewReader(fp)
    reader.Comma = ','
    reader.LazyQuotes = true
    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        } else if err != nil {
            panic(err)
        }
        fmt.Println(record)
    }
}


func main(){
    userCsvNewReader("pa_2行.log")
}