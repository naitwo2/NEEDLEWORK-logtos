//Todo
//Dest-NATはでDest-ipと逆にしないと
//tomlからFW-IP情報を読みとる

package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"
	"encoding/csv"
	//"github.com/nirasan/environment-toml"
)

type ScenarioLine struct {
	logtype string
	srcip string
	destip string
	natsrcip string
	natdestip string
	rulename string
	ininterface string
	outinterface string
	srcport string
	destport string								
	natsrcport string
	natdestport string		
	protocol string		
	action string	
}


func main() {
	baseLogData , err := readLine("pa_10000行.log")
	
	if err != nil {
        //fmt.Println(os.Stderr, err)
        os.Exit(1)
	}
	
	err = genScenario(baseLogData)

	//fmt.Println(logdata)
	//println(j)
}



func readLine(filename string) ([]ScenarioLine , error) {
	var logdata []ScenarioLine

    file, err := os.Open(filename)
    if err != nil {
        return logdata , err
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
       		return logdata , err
        }
		
		// カンマでスプリット
		slice := strings.Split(string(line), ",")

		//スプリットした値をMAPに代入
		logdataLineMap := make(map[string]string)
  		for i, str := range slice {
			switch(i){
				case 3:
					logdataLineMap["logtype"] = str
				case 7:
					logdataLineMap["srcip"] = str
				case 8:
					logdataLineMap["destip"] = str
				case 9:
					logdataLineMap["natsrcip"] = str
				case 10:
					logdataLineMap["natdestip"] = str
				case 11:
					logdataLineMap["rulename"] = str
				case 18:
					logdataLineMap["ininterface"] = str
				case 19:
					logdataLineMap["outinterface"] = str
				case 24:
					logdataLineMap["srcport"] = str
				case 25:
					logdataLineMap["destport"] = str
				case 26:
					logdataLineMap["natsrcport"] = str
				case 27:
					logdataLineMap["natdestport"] = str
				case 29:
					logdataLineMap["protocol"] = str
				case 30:
					logdataLineMap["action"] = str
			}
		}  

        if !isPrefix {
            fmt.Println()
		}

		//----値をシナリオ対応用語に変更----
		//Action
		switch(logdataLineMap["action"]){
			case "allow":
				logdataLineMap["action"] = "pass"
			case "deny":
				logdataLineMap["action"] = "drop"				
			default:
				logdataLineMap["action"] = "undefined"
		}

		//DestNATIP 作成中
		switch{
			case logdataLineMap["natdestip"] ==  "0.0.0.0":
				logdataLineMap["natdestip"] = ""
			case logdataLineMap["natdestip"] != "":
				//logdataLineMap["natdestip"] = "DstNATしてる"
		}

		//SrcNATIP
		switch{
			case logdataLineMap["natsrcip"] == "0.0.0.0":
				logdataLineMap["natsrcip"] = ""

		}

		//SrcPort
		switch{
			case logdataLineMap["srcport"] == "0":
				logdataLineMap["srcport"] = ""
		}
		//DestPort
		switch{
			case logdataLineMap["destport"] == "0":
				logdataLineMap["destport"] = ""
		}
		//NatDestPort
		switch{
			case logdataLineMap["natdestport"] == "0":
				logdataLineMap["natdestport"] = ""
		}
		//NatSrcPort
		switch{
			case logdataLineMap["natsrcport"] == "0":
				logdataLineMap["natsrcport"] = ""
		}

		//----End 値をシナリオ対応用語に変更----

		//MAPに入れた値をスライスに代入（e.g: TRAFFIC 172.16.20.238...）
		logdata = append(logdata, ScenarioLine{logdataLineMap["logtype"],logdataLineMap["srcip"],logdataLineMap["destip"],logdataLineMap["natsrcip"],logdataLineMap["natdestip"],logdataLineMap["rulename"],logdataLineMap["ininterface"],logdataLineMap["outinterface"],logdataLineMap["srcport"],logdataLineMap["destport"],logdataLineMap["natsrcport"],logdataLineMap["natdestport"],logdataLineMap["protocol"],logdataLineMap["action"]})

		j =  j + 1
		/* fmt.Println(logdata)
		fmt.Println(logdata[0])
		fmt.Println(logdata[0].logtype)
 */
	}

    return logdata , nil
}

func genScenario(baseLogData []ScenarioLine) error {

	//CSVファイルを新規作成
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

//fmt.Println(baseLogdata)

/* 	for i := 0; i < 5; i++ {
		fmt.Println(i) // 0 1 2 3 4が出力される
		fmt.Println(logdata)
	} */

	//ヘッダー情報書き込み
	writer.Write([]string{"exclude-list","protocol","src-fw","src-vlan(option)","src-ip","src-port(option)","src-nat-ip(option)","dst-fw","dst-vlan(option)","dst-nat-ip(option)","dst-nat-port (option)","dst-ip","dst-port","url/domain(option)","anti-virus(option)","timeout(option)","try(option)","other-settings(option)","expect","description"})
	
	for _, value := range baseLogData {
		//fmt.Printf("key:%i -> value=%s\n", key, value)
		//fmt.Println(value[0].logtype)
		//fmt.Println(value.logtype)
		writer.Write([]string{"",value.protocol , "s-fw" , "s-vlan" , value.srcip , value.srcport , value.natsrcip , "dst-fw" , "dst-vlan" , value.natdestip , value.natdestport , value.destip , value.destport, "" , "" , "", "" , "" , value.action , value.rulename})     
	}
	
	writer.Flush() 

	return nil
}