// Command launcher-port reads only the configured listener port without loading credentials.
package main

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "错误：无法读取配置端口：%v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("需要一个配置文件路径")
	}
	data, errRead := os.ReadFile(args[0])
	if errRead != nil {
		return fmt.Errorf("读取配置文件失败：%w", errRead)
	}
	port, errParse := parsePort(data)
	if errParse != nil {
		return errParse
	}
	_, errWrite := fmt.Fprintln(output, port)
	return errWrite
}

func parsePort(data []byte) (int, error) {
	var root map[string]yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0, fmt.Errorf("配置不是有效的 YAML：%w", err)
	}
	portNode, present := root["port"]
	if server, exists := root["server"]; exists {
		var settings map[string]yaml.Node
		if err := server.Decode(&settings); err != nil || settings == nil {
			return 0, fmt.Errorf("server 必须是 YAML 映射")
		}
		if current, exists := settings["port"]; exists {
			portNode, present = current, true
		}
	}
	if !present {
		return 0, nil
	}
	// Presence wins over legacy values, including null and zero, matching v8 config loading.
	var port int
	if err := portNode.Decode(&port); err != nil {
		return 0, fmt.Errorf("port 必须是整数或空值")
	}
	return port, nil
}
