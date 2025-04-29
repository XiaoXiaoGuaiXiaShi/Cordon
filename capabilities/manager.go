package capabilities

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"cordon/config"
	log "cordon/log"

	"github.com/aquasecurity/libbpfgo"
)

const (
	CAPABILITY_CONFIG = "cap_config_map"
	TARGET_MAP_PID = "cap_pids"
	MODE_MONITOR      = uint32(0)
	MODE_BLOCK        = uint32(1)
)

// CAP_NAMES 定义了 CAP 名称与序号的映射
var CAP_NAMES = map[string]uint8{
    "CAP_CHOWN":              0,
    "CAP_DAC_OVERRIDE":       1,
    "CAP_DAC_READ_SEARCH":    2,
    "CAP_FOWNER":             3,
    "CAP_FSETID":             4,
    "CAP_KILL":               5,
    "CAP_SETGID":             6,
    "CAP_SETUID":             7,
    "CAP_SETPCAP":            8,
    "CAP_LINUX_IMMUTABLE":    9,
    "CAP_NET_BIND_SERVICE":   10,
    "CAP_NET_BROADCAST":      11,
    "CAP_NET_ADMIN":          12,
    "CAP_NET_RAW":            13,
    "CAP_IPC_LOCK":           14,
    "CAP_IPC_OWNER":          15,
    "CAP_SYS_MODULE":         16,
    "CAP_SYS_RAWIO":          17,
    "CAP_SYS_CHROOT":         18,
    "CAP_SYS_PTRACE":         19,
    "CAP_SYS_PACCT":          20,
    "CAP_SYS_ADMIN":          21,
    "CAP_SYS_BOOT":           22,
    "CAP_SYS_NICE":           23,
    "CAP_SYS_RESOURCE":       24,
    "CAP_SYS_TIME":           25,
    "CAP_SYS_TTY_CONFIG":     26,
    "CAP_MKNOD":              27,
    "CAP_LEASE":              28,
    "CAP_AUDIT_WRITE":        29,
    "CAP_AUDIT_CONTROL":      30,
    "CAP_SETFCAP":            31,
    "CAP_MAC_OVERRIDE":       32,
    "CAP_MAC_ADMIN":          33,
    "CAP_SYSLOG":             34,
    "CAP_WAKE_ALARM":         35,
    "CAP_BLOCK_SUSPEND":      36,
    "CAP_AUDIT_READ":         37,
    "CAP_PERFMON":            38,
    "CAP_BPF":                39,
    "CAP_CHECKPOINT_RESTORE": 40,
}

type Manager struct {
    mod    *libbpfgo.Module
    config *config.Config
    rb     *libbpfgo.RingBuffer
}

func (m *Manager) setMode() error {
	key := make([]byte, 8)
	configMap, err := m.mod.GetMap(CAPABILITY_CONFIG)
	if err != nil {
		return err
	}

	if m.config.IsRestrictedMode("capabilities") {
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

func (m *Manager) setAllowedCapabilityMap() error {
	map_allowed_caps, err := m.mod.GetMap(ALLOWED_CAPABILITIES_MAP_NAME)
	if err != nil {
		return err
	}

	allowed_caps := m.config.RestrictedCapabilityConfig.Allow

	for i, cap := range allowed_caps {
		key := uint8(i)
		capSeq, ok := CAP_NAMES[cap]
		if !ok {
            return fmt.Errorf("unknown capability: %s", cap)
        }
		err = map_allowed_caps.Update(unsafe.Pointer(&key), unsafe.Pointer(&capSeq))
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) setDeniedCapabilityMap() error {
	map_denied_caps, err := m.mod.GetMap(DENIED_CAPABILITIES_MAP_NAME)
	if err != nil {
		return err
	}
	denied_caps := m.config.RestrictedCapabilityConfig.Deny

	for i, cap := range denied_caps {
		key := uint8(i)
		capSeq, ok := CAP_NAMES[cap]
		if !ok {
            return fmt.Errorf("unknown capability: %s", cap)
        }
		err = map_denied_caps.Update(unsafe.Pointer(&key), unsafe.Pointer(&capSeq))
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
		return err
	}

	err = m.setAllowedCapabilityMap()
	if err != nil {
		return err
	}

	err = m.setDeniedCapabilityMap()
	if err != nil {
		return err
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
	rb, err := m.mod.InitRingBuf("capcontrol_events", eventsChannel)
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