package syscalls

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"cordon/config"
	log "cordon/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	SYSCONTROL_CONFIG = "sys_config_map"
	TARGET_MAP_PID = "bpf_pids"
	MODE_MONITOR      = uint32(0)
	MODE_BLOCK        = uint32(1)

)

type Manager struct {
    mod    *libbpfgo.Module
    config *config.Config
    rb     *libbpfgo.RingBuffer
}

func (m *Manager) setMode() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(SYSCONTROL_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("bpf") {
		binary.LittleEndian.PutUint32(key[0:4], MODE_BLOCK)
	} else {
		binary.LittleEndian.PutUint32(key[0:4], MODE_MONITOR)
	}

	// 添加键值对，其键是一个8位无符号整数k，值是key。
	k := uint8(0)
	err = configMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&key[0]))
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) setContainerMap() error {
	containerMap, err := m.mod.GetMap(TARGET_MAP_PID)
	if err != nil {
		return err
	}
	target_layer := m.config.TargetConfig.Layer
	pids := m.config.GetPids(target_layer)
	if pids == nil {
		return err
	}

	for i, pid := range pids {
		key := uint8(i)
		// 注意：将pid转换为byte slice
		pidBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(pidBytes, pid)

		err := containerMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&pidBytes[0]))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) SetConfigToMap() error {
	err := m.setMode()
	if err != nil {
		return err
	}

	container_err := m.setContainerMap()
	if container_err != nil {
		return container_err
	}

	return nil
}

func (m *Manager) Attach() error {
	trigger_prog, err := m.mod.GetProgram("task_alloc")
	if err != nil {
		return err
	}
	_, err = trigger_prog.AttachLSM()
	if err != nil {
		return err
	}
	log.Debug(fmt.Sprintf("trigger_prog attached."))

	prog, err := m.mod.GetProgram(BPF_PROGRAM_NAME)
	if err != nil {
		return err
	}
	_, err = prog.AttachLSM()
	if err != nil {
		return err
	}
	log.Debug(fmt.Sprintf("%s attached.", BPF_PROGRAM_NAME))
	
	return nil
}


func (m *Manager) Start(eventsChannel chan []byte) error {
	rb, err := m.mod.InitRingBuf("syscontrol_events", eventsChannel)
	if err != nil {
		return err
	}

	rb.Start()
	m.rb = rb

	return nil
}

func (m *Manager) Stop() {
	m.rb.Stop()
}

func (m *Manager) Close() {
	m.rb.Close()
}