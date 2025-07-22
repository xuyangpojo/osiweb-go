package main

import "fmt"

func main() {
	cfg, err := loadConfig("config.json")
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		return
	}
	fmt.Println(" ██████╗ ███████╗██╗██╗    ██╗███████╗██████╗      ██████╗  ██████╗ ")
	fmt.Println("██╔═══██╗██╔════╝██║██║    ██║██╔════╝██╔══██╗    ██╔════╝ ██╔═══██╗")
	fmt.Println("██║   ██║███████╗██║██║ █╗ ██║█████╗  ██████╔╝    ██║  ███╗██║   ██║")
	fmt.Println("██║   ██║╚════██║██║██║███╗██║██╔══╝  ██╔══██╗    ██║   ██║██║   ██║")
	fmt.Println("╚██████╔╝███████║██║╚███╔███╔╝███████╗██████╔╝    ╚██████╔╝╚██████╔╝")
	fmt.Println(" ╚═════╝ ╚══════╝╚═╝ ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═════╝  ╚═════╝ ")
	fmt.Println("欢迎使用 OSIWeb-Go !")
	for {
		line, err := inputHandler.ReadLine("gkv> ")
		if err != nil {
			if err.Error() == "用户中断" {
				fmt.Println("再见! :D")
				return
			}
			if err.Error() == "EOF" {
				fmt.Println("再见! :D")
				return
			}
			fmt.Printf("输入错误: %v\n", err)
			continue
		}
		inputHandler.saveCurrentLine(line)
		fields := parseFields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "set":
			if len(fields) != 3 {
				fmt.Println("参数错误!")
				fmt.Println("用法: set \"key\" \"value\"")
				continue
			}
			data.DataGkvString.Set(fields[1], []byte(fields[2]))
			fmt.Println("OK")
		case "get":
			if len(fields) != 2 {
				fmt.Println("参数错误!")
				fmt.Println("用法: get \"key\"")
				continue
			}
			v, ok := data.DataGkvString.Get(fields[1])
			if ok {
				fmt.Println(string(v))
			} else {
				fmt.Println("(nil)")
			}
		case "setnx":
			if len(fields) != 3 {
				fmt.Println("参数错误!")
				fmt.Println("用法: setnx \"key\" \"value\"")
				continue
			}
			if data.DataGkvString.SetNX(fields[1], []byte(fields[2])) {
				fmt.Println("OK")
			} else {
				fmt.Println("插入失败,Key已存在")
			}
		case "setxx":
			if len(fields) != 3 {
				fmt.Println("参数错误!")
				fmt.Println("用法: setxx \"key\" \"value\"")
				continue
			}
			if data.DataGkvString.SetXX(fields[1], []byte(fields[2])) {
				fmt.Println("OK")
			} else {
				fmt.Println("插入失败,Key不存在")
			}
		case "del":
			if len(fields) != 2 {
				fmt.Println("参数错误!")
				fmt.Println("用法: del \"key\"")
				continue
			}
			data.DataGkvString.Delete(fields[1])
			fmt.Println("OK")
		case "keys":
			if len(fields) != 1 {
				fmt.Println("参数错误!")
				fmt.Println("用法: keys")
				continue
			}
			keys := data.DataGkvString.GetAllKeys()
			if len(keys) == 0 {
				fmt.Println("(empty list or set)")
			} else {
				for i, key := range keys {
					if i > 0 {
						fmt.Print(" ")
					}
					fmt.Printf("\"%s\"", key)
				}
				fmt.Println()
			}
		case "kvs":
			if len(fields) != 1 {
				fmt.Println("参数错误!")
				fmt.Println("用法: kvs")
				continue
			}
			kvs := data.DataGkvString.GetAllKVs()
			if len(kvs) == 0 {
				fmt.Println("(empty list or set)")
			} else {
				for k, v := range kvs {
					fmt.Println(k, " -> ", v)
				}
			}
		case "settime":
			if len(fields) != 3 {
				fmt.Println("参数错误!")
				fmt.Println("用法: settime \"key\" (milliseconds)")
				continue
			}
			num, _ := strconv.Atoi(fields[2])
			data.DataGkvString.SetTime(fields[1], num)
		case "getlasttime":
			if len(fields) != 2 {
				fmt.Println("参数错误!")
				fmt.Println("用法: getlasttime \"key\"")
				continue
			}
			ttl := data.DataGkvString.GetTTL(fields[1])
			switch ttl {
			case -1:
				fmt.Println("(nil)")
			case -2:
				fmt.Println("已过期")
			default:
				fmt.Printf("%d\n", ttl)
			}
		case "help":
			showHelp()
		case "quit":
			fmt.Println("再见! :D")
			return
		default:
			fmt.Println("未知命令: ", fields[0])
			showSimilarCommands(fields[0])
		}
	}
}
