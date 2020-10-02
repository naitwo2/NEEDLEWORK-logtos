//Todo
//Dest-NATはでDest-ipと逆にしないと
//ZONE情報をログから取り入れる
//TOMLにVLAN情報入れる

package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"
	"encoding/csv"
	"github.com/BurntSushi/toml"
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

type TomlConfig struct {
	Device		DeviceConfig		
}

type DeviceConfig struct {
	Device		string			`toml:"devicename"`
	Interface	[]NetworkConfig	`toml:"interface"`
}

type NetworkConfig struct {
    Ifname	string	 `toml:"ifname"`
	Ip		string	 `toml:"ip"`
	Zone	string	 `toml:"zone"`
}


func main() {

	baseLogData , err := readLine("pa_2行.log")
	
	if err != nil {
        //fmt.Println(os.Stderr, err)
        os.Exit(1)
	}
	
	err = genScenario(baseLogData , "config.tml")

	//fmt.Println(logdata)
	//println(j)
}


//logファイルを読み込む
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

func genScenario(baseLogData []ScenarioLine , tomlFile string ) error {

	//Tomlファイル読み込み
	var config TomlConfig
	_, err := toml.DecodeFile(tomlFile, &config)
  	if err != nil {
        return err
    }
	//fmt.Println(config.Interface.IP)
	fmt.Println(config)
	fmt.Println(config.Device.Interface[0].Ifname)


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

	//シナリオヘッダー情報書き込み
	writer.Write([]string{"exclude-list","protocol","src-fw","src-vlan(option)","src-ip","src-port(option)","src-nat-ip(option)","dst-fw","dst-vlan(option)","dst-nat-ip(option)","dst-nat-port (option)","dst-ip","dst-port","url/domain(option)","anti-virus(option)","timeout(option)","try(option)","other-settings(option)","expect","description"})
	
	//スライスに格納したログを取り出し、シナリオを作成する
	sfw  := "Undefined"
	dfw  := "Undefined"
	for _, value := range baseLogData {
		//fmt.Printf("key:%i -> value=%s\n", key, value)
		//fmt.Println(value[0].logtype)
		//fmt.Println(value.logtype)

		//Tomlファイルに記載したIF情報とログ中のIN/OUT IF情報を比較する
		for _, tomlValue := range config.Device.Interface {

			switch{
				case value.ininterface == tomlValue.Ifname:
					sfw = tomlValue.Ip
				case value.outinterface == tomlValue.Ifname:
					dfw = tomlValue.Ip
				//out IFが空 = 通信がDropされた場合の処理
				//case value.outinterface == "":
				//	if value.ininterface == tomlValue.Zone
			}

		}


		writer.Write([]string{"",value.protocol , sfw , "s-vlan" , value.srcip , value.srcport , value.natsrcip , dfw , "dst-vlan" , value.natdestip , value.natdestport , value.destip , value.destport, "" , "" , "", "" , "" , value.action , value.rulename})     
	}
	
	writer.Flush() 

	return nil
}