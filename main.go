//Todo
//戻り値にmapを指定できない
//戻り値が足りない。err以外に返さないと。

package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"
	"encoding/csv"
)

type mapKey struct {
	k1 int
	k2 string	
}

func main() {
	logdata , err := readLine("pa_2行.log")
	
	if err != nil {
        fmt.Println(os.Stderr, err)
        os.Exit(1)
	}
	
	err = genScenario(logdata)

	//fmt.Println(logdata)
	//println(j)
}



func readLine(filename string) (map[mapKey]string , error) {

	//logdataMap := map[int]map[string]string{}
	logdataMap := make(map[mapKey]string)

    file, err := os.Open(filename)
    if err != nil {
        return logdataMap , err
    }
    defer file.Close()

    reader := bufio.NewReader(file)

	//logdataMapのindexとして利用
	j := 0
	//ログを1行ごと読み込む
    for {
        line, isPrefix, err := reader.ReadLine()
        if err == io.EOF {
            break
        }
        if err != nil {
       		return logdataMap , err
        }
		
		// カンマでスライス
		slice := strings.Split(string(line), ",")

		//スライスした値をMAPに代入
  		for i, str := range slice {
			switch(i){
				case 3:
					logdataMap[mapKey{j, "type"}] = str
				case 7:
					logdataMap[mapKey{j, "srcip"}] = str
				case 8:
					logdataMap[mapKey{j, "destip"}] = str
				case 9:
					logdataMap[mapKey{j, "natsrcip"}] = str
				case 10:
					logdataMap[mapKey{j, "natdestip"}] = str
				case 11:
					logdataMap[mapKey{j, "rulename"}] = str		
				case 18:
					logdataMap[mapKey{j, "ininterface"}] = str	
				case 19:
					logdataMap[mapKey{j, "outinterface"}] = str	
				case 24:
					logdataMap[mapKey{j, "srcport"}] = str	
				case 25:
					logdataMap[mapKey{j, "destport"}] = str	
				case 26:
					logdataMap[mapKey{j, "natsrcport"}] = str	
				case 27:
					logdataMap[mapKey{j, "natdestport"}] = str	
				case 29:
					logdataMap[mapKey{j, "protocol"}] = str	
				case 30:
					logdataMap[mapKey{j, "action"}] = str	
			}
		}  

        if !isPrefix {
            fmt.Println()
		}
		j =  j + 1
	}

	//fmt.Println(logdataMap)
    return logdataMap , nil
}

func genScenario(logdata map[mapKey]string) error {


	file, err := os.Create("NEEDLEWORK_Scenario.csv")

    if err != nil {
        return err
    }
	defer file.Close()
	
	//ファイルの中身を空にする
	err = file.Truncate(0)

    if err != nil {
        return err
	}
	
	writer := csv.NewWriter(file) // utf8
	//writer.Write([]string{"Alice", "20"})        
	//writer.Write(logdata{1 "srcip"})        

fmt.Println(logdata[[0],["destip"]])

/* 	for i := 0; i < 5; i++ {
		fmt.Println(i) // 0 1 2 3 4が出力される
		fmt.Println(logdata)
	} */

/*     for _, value := range logdata {
		//fmt.Printf("key:%i -> value=%s\n", key, value)
		fmt.Println(key)
		writer.Write([]string{value , ","})     
	} */
	
	writer.Flush() 

return nil
}