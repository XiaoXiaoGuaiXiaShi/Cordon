package syscalls

import (
	"context"
	"sync"
	"bytes"
	"encoding/binary"
	"io"

	"cordon/config"
	"cordon/bpf"
	log "cordon/log"
	"cordon/helpers"

	"github.com/aquasecurity/libbpfgo"
)

const (
	BPF_OBJECT_NAME        = "bpf_syscall_control"
	BPF_PROGRAM_NAME       = "bpf_syscall_control"

	NEW_UTS_LEN   = 64
	TASK_COMM_LEN = 16
)

type auditLog struct {
	CGroupID      uint64
	PID           uint32
	Ret           int32
	Nodename      [NEW_UTS_LEN + 1]byte
	Command       [TASK_COMM_LEN]byte
	ParentCommand [TASK_COMM_LEN]byte
	Syscall          [4]byte
}

func setupBPFProgram() (*libbpfgo.Module, error) {
	bytecode, err := bpf.EmbedFS.ReadFile("bytecode/syscall_control.bpf.o")
	if err != nil {
		return nil, err
	}
	mod, err := libbpfgo.NewModuleFromBuffer(bytecode, BPF_OBJECT_NAME)
	if err != nil {
		return nil, err
	}

	if err = mod.BPFLoadObject(); err != nil {
		return nil, err
	}

	return mod, nil
}

func RunAudit(ctx context.Context, wg *sync.WaitGroup, conf *config.Config) error {
	log.Info("Launching the bpf_prog audit...")
	defer wg.Done()

	if !conf.RestrictedSyscallConfig.Enable {
		log.Info("bpf_prog audit is disable. shutdown...")
		return nil
	}

	mod, err := setupBPFProgram()
	if err != nil {
		log.Fatal(err)
	}
	defer mod.Close()

	mgr := Manager{
		mod:    mod,
		config: conf,
	}

	mgr.SetConfigToMap()
	if err != nil {
		log.Fatal(err)
	}

	mgr.Attach()

	log.Info("Start the bpf_prog audit.")
	eventsChannel := make(chan []byte)
	mgr.Start(eventsChannel)

	go func() {
		for {
			eventBytes := <-eventsChannel
			event, err := parseEvent(eventBytes)
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error(err)
				continue
			}

			auditLog := newAuditLog(event)
			auditLog.Info()
		}
	}()

	<-ctx.Done()
	mgr.Close()
	log.Info("Terminated the fileaccess audit.")

	return nil
}

func parseEvent(eventBytes []byte) (auditLog, error) {
	buf := bytes.NewBuffer(eventBytes)
	var event auditLog
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		return auditLog{}, err
	}

	return event, nil
}

func retToaction(ret int32) string {
	if ret == 0 {
		return "ALLOWED"
	} else {
		return "BLOCKED"
	}
}

func newAuditLog(event auditLog) log.RestrictedSyscallLog {
	auditEvent := log.AuditEventLog{
		Action:     retToaction(event.Ret),
		Hostname:   helpers.NodenameToString(event.Nodename),
		PID:        event.PID,
		Comm:       helpers.CommToString(event.Command),
		ParentComm: helpers.CommToString(event.ParentCommand),
	}

	sysControlLog := log.RestrictedSyscallLog{
		AuditEventLog: auditEvent,
		Syscall:          "bpf_prog",
	}

	return sysControlLog
}