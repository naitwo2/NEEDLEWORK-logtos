//Todo
//同じZoneが複数IFに割り当てられている場合にシナリオ複数

package main

import (
    "bufio"
    "fmt"
    "io"
	"os"
	"strings"
	"encoding/csv"
	"github.com/BurntSushi/toml"
	"flag"
)

type ScenarioLine struct {
	logtype string
	srcip string
	destip string
	natsrcip string
	natdestip string
	rulename string
	srczone string
	destzone string	
	ininterface string
	outinterface string
	srcport string
	destport string								
	natsrcport string
	natdestport string		
	protocol string		
	action string	
	description string	
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
	Vlanid	string	 `toml:"vlanid"`	
}

func main() {
    var (
        flgCfg = flag.String("c", "config.tml", "specification a config file.")
		
    )
	flag.Parse()
    args := flag.Args()
	baseLogData , err := readLine(args[0])

	if err != nil {
		fmt.Println(err)
        os.Exit(1)
	}
	
	err = genScenario(baseLogData , *flgCfg)

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
				case 16:
					logdataLineMap["srczone"] = str
				case 17:
					logdataLineMap["destzone"] = str
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

		//想定しない値があった場合にdescriptionに追記する
		logdataLineMap["description"] = " ,"

		//----値をシナリオ対応用語に変更----
		//Action
		switch(logdataLineMap["action"]){
			case "allow":
				logdataLineMap["action"] = "pass"
			case "deny":
				logdataLineMap["action"] = "drop"				
			default:
				logdataLineMap["description"] += " | exception(action:" + logdataLineMap["action"] + ")"
				logdataLineMap["action"] = "undefined"
		}

		//DestNATIP
		//DestNATしている場合は、宛先と宛先NATIPを入れ替えてシナリオを作成する
		switch{
			case logdataLineMap["natdestip"] ==  "0.0.0.0":
				logdataLineMap["natdestip"] = ""
			case logdataLineMap["natdestip"] != "":
				tmpVar := logdataLineMap["destip"]
				logdataLineMap["destip"] = logdataLineMap["natdestip"]
				logdataLineMap["natdestip"] = tmpVar
				//宛先ポートとNAT宛先ポートの入れ替え
				tmpVar = logdataLineMap["destport"]
				logdataLineMap["destport"] = logdataLineMap["natdestport"]
				logdataLineMap["natdestport"] = tmpVar
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
		//Protocol
		switch{
			case logdataLineMap["protocol"] == "icmp" || logdataLineMap["protocol"] == "tcp" || logdataLineMap["protocol"] == "udp":
				break
			default:
				logdataLineMap["description"] += " | exception(protocol:" + logdataLineMap["protocol"] + ")"
				logdataLineMap["protocol"] = "undefined"	
		}

		//----End 値をシナリオ対応用語に変更----

		//MAPに入れた値をスライスに代入（e.g: TRAFFIC 172.16.20.238...）
		logdata = append(logdata, ScenarioLine{logdataLineMap["logtype"],logdataLineMap["srcip"],logdataLineMap["destip"],logdataLineMap["natsrcip"],logdataLineMap["natdestip"],logdataLineMap["rulename"],logdataLineMap["srczone"],logdataLineMap["destzone"],logdataLineMap["ininterface"],logdataLineMap["outinterface"],logdataLineMap["srcport"],logdataLineMap["destport"],logdataLineMap["natsrcport"],logdataLineMap["natdestport"],logdataLineMap["protocol"],logdataLineMap["action"],logdataLineMap["description"]})

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
	//fmt.Println(config)
	//fmt.Println(config.Device.Interface[0].Ifname)


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

	//シナリオヘッダー情報書き込み
	writer.Write([]string{"exclude-list","protocol","src-fw","src-vlan(option)","src-ip","src-port(option)","src-nat-ip(option)","dst-fw","dst-vlan(option)","dst-nat-ip(option)","dst-nat-port (option)","dst-ip","dst-port","url/domain(option)","anti-virus(option)","timeout(option)","try(option)","other-settings(option)","expect","description"})

	//スライスに格納したログを取り出し、シナリオを作成する
	sfw		:= "Undefined"
	//var dfw		[]string
	var newDfw	[]string
	svlan	:= "0"
	dvlan 	:= "0"
	// description := ""
	for _, value := range baseLogData {

		//Tomlファイルに記載したIF情報とログ中のIN/OUT IF情報を比較し、s-fw、d−fwのIPアドレスを割り当てる
		//i := 0
		for _, tomlValue := range config.Device.Interface {
			
			switch{
				//out IFが空 = Dropログの場合の処理（Zoneからs-fw、d−fwのIPアドレスを割り当てる）
				case value.outinterface == "":
					fmt.Println(value.outinterface)
					if value.destzone == tomlValue.Zone {
						newDfw  = append(newDfw, tomlValue.Ip)
						//i ++
						fmt.Println(newDfw)
					} else{
						newDfw = append(newDfw, "Undefined")
						value.description += " | exception(s-fw or d-fw)"
					}
				case value.ininterface == tomlValue.Ifname:
					sfw = tomlValue.Ip
					svlan = tomlValue.Vlanid
				case value.outinterface == tomlValue.Ifname:
					newDfw  = append(newDfw, tomlValue.Ip)
					dvlan = tomlValue.Vlanid
				default:
					newDfw = append(newDfw, "Undefined")
					value.description += " | exception(s-fw or d-fw)" 

			}
		}

		//fmt.Println(dfw)
		//シナリオの組み立て
		for _, dfwMulti := range newDfw {
			writer.Write([]string{"",value.protocol , sfw , svlan , value.srcip , value.srcport , value.natsrcip , dfwMulti , dvlan , value.natdestip , value.natdestport , value.destip , value.destport, "" , "" , "", "" , "" , value.action , value.rulename , value.description})     
		}
	}
	
	writer.Flush() 

	return nil
}