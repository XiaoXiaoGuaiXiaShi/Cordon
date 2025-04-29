package config

import (
	"os"
	"bytes"
    "fmt"
    "os/exec"
    "strings"
	"gopkg.in/yaml.v2"

	log "cordon/log"
)

type RestrictedFileAccessConfig struct {
	Enable bool
	Mode   string   `yaml:"mode"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
}

type RestrictedCapabilityConfig struct {
	Enable bool
	Mode   string   `yaml:"mode"`
	Allow  []string `yaml:"allow"`
	Deny   []string `yaml:"deny"`
}

type RestrictedSyscallConfig struct {
	Enable bool
	Mode   string   `yaml:"mode"`
}

type TargetConfig struct {
	Enable        bool     `yaml:"enable"`
	Layer     string `yaml:"target_layer"`
	Info    InfoConfig    `yaml:"target_info"`
}

type InfoConfig struct {
	Name   []string   `yaml:"name"`
	Label  []string `yaml:"label"`
	Pid   []uint32 `yaml:"pid"`
}

type LogConfig struct {
	Level   string            `yaml:"level"`
	Format  string            `yaml:"format"`
	Output  string            `yaml:"output"`
	MaxSize int               `yaml:"max_size"`
	MaxAge  int               `yaml:"max_age"`
	Labels  map[string]string `yaml:"labels"`
}

type Config struct {
	RestrictedFileAccessConfig    `yaml:"files"`
	RestrictedCapabilityConfig `yaml:"capabilities"`
	RestrictedSyscallConfig      `yaml:"bpf"`
	TargetConfig             `yaml:"objectives"`
	Log                        LogConfig
}

func DefaultConfig() *Config {
	return &Config{
		RestrictedFileAccessConfig: RestrictedFileAccessConfig{
			Enable: true,
			Mode:   "monitor",
			Allow:  []string{"/"},
			Deny:   []string{},
		},
		RestrictedCapabilityConfig: RestrictedCapabilityConfig{
			Enable:  true,
			Mode:    "monitor",
			Allow:  []string{"/"},
			Deny:   []string{},
		},
		RestrictedSyscallConfig: RestrictedSyscallConfig{
			Enable:         true,
			Mode:           "monitor",
		},
		TargetConfig: TargetConfig{
			Enable:        false,
			Layer:     "container",
			Info: InfoConfig{Name: []string{"test1", "test2"}, Label: []string{}, Pid: []uint32{}},
		},
		Log: LogConfig{
			Level:  "INFO",
			Format: "json",
			Output: "stdout",
			Labels: map[string]string{},
		},
	}
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	config := DefaultConfig()
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) IsRestrictedMode(target string) bool {
	switch target {
	case "capabilities":
		if c.RestrictedCapabilityConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "fileaccess":
		if c.RestrictedFileAccessConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	case "bpf":
		if c.RestrictedSyscallConfig.Mode == "block" {
			return true
		} else {
			return false
		}
	default:
		return false
	}
}

func (c *Config) GetPids(target_layer string) []uint32 {
	switch target_layer {
	case "node":
		pids := []uint32{1}
		return pids
	case "container":
		// 调用 GetTarget 函数并获取 PIDs
		pids, err := c.GetContainerTarget(c.TargetConfig.Info.Name)
		if err != nil {
			return nil
		}
		return pids
	// case "deployment":
	// 	// 调用 GetTarget 函数并获取 PIDs
	// 	pids, err := m.config.GetDeploymentTarget()
	// 	if err != nil {
	// 		return err
	// 	}
	case "pid":
		pids := c.TargetConfig.Info.Pid
		return pids
	default:
		return []uint32{1}
	}
}

// GetContainerTarget函数，去匹配所有name的容器，然后返回所有容器的入口点程序的PID
func (c *Config) GetContainerTarget(names []string) ([]uint32,error) {
	var result []uint32 // 使用切片保存pids
	for _, name := range names {
        // 执行 docker top 命令来获取容器内的进程
        cmd := exec.Command("docker", "top", name, "-eo", "pid")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
			log.Fatal(fmt.Errorf("failed to run docker top for container %s: %w", name, err))
            return nil, err
        }

        pids, err := parsePIDs(out.String())
        if err != nil {
			log.Fatal(fmt.Errorf("failed to parse PIDs for container %s: %w", name, err))
            return nil, err
        }
		result = append(result, pids...)  // 将pid加入到切片中
    }

	fmt.Printf("All PIDs: %v\n", result)
    return result, nil
}

// parsePIDs 解析 docker top 命令的输出并提取 PID 列表
func parsePIDs(output string) ([]uint32, error) {
    lines := strings.Split(output, "\n")
    var pids []uint32
    for i, line := range lines {
        // 跳过首行，因为它包含字段名称
        if i == 0 {
            continue
        }
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        var pid uint32
        if _, err := fmt.Sscanf(line, "%d", &pid); err != nil {
            return nil, fmt.Errorf("failed to parse line %q: %w", line, err)
        }
        pids = append(pids, pid)
    }
    return pids, nil
}