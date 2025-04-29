package main

import (
	"os"
	"errors"
	"os/signal"
	"context"
	"sync"

	"cordon/config"
	"cordon/utils"
	"cordon/fileaccess"
	"cordon/capabilities"
	"cordon/syscalls"
	log "cordon/log"

	"github.com/urfave/cli/v2"
)

var (
	configFlag = cli.StringFlag{
		Name:    "config",
		Value:   "policy/default.yaml",
		Usage:   "config file path",
	}
)

func main() {
	app := cli.NewApp()
	app.Name = "cordon"
	app.Usage = "Container Security Protection."
	flags := []cli.Flag{&configFlag}
	app.Flags = flags

	app.Action = func(c *cli.Context) error {
		path := c.String("config")
		conf, err := config.NewConfig(path)
		if err != nil {
			log.Error(err)
			return nil
		}

		// 使用fmt.Println()或log.Println()将配置信息输出到控制台
		// log.Println(conf)

		if !utils.AmIRootUser() {
			return errors.New("Must be run as root user.")
		}
		docker_flag, err := utils.RunningInDocker()
		if err != nil {
			log.Error(err)
			return nil
		}
		if docker_flag {
			return errors.New("Cannot be run in container.")
		}
		// log.Println("Right config!")

		log.SetFormatter(conf.Log.Format)
		log.SetOutput(conf.Log.Output)
		log.SetRotation(conf.Log.Output, conf.Log.MaxSize, conf.Log.MaxAge)
		log.SetLabel(conf.Log.Labels)
		log.SetLevel(conf.Log.Level)

		// 接受操作系统发送的信号，如中断
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(3)

		go fileaccess.RunAudit(ctx, &wg, conf)
		go capabilities.RunAudit(ctx, &wg, conf)
		go syscalls.RunAudit(ctx, &wg, conf)

		wg.Wait()
		log.Info("Terminate all audit.")
		return nil
	}

	// 添加环境检查，内核版本及相关模块是否支持
	err := utils.IsCompatible()
	if err != nil {
		log.Error(err)
	}

	app_err := app.Run(os.Args)
	if app_err != nil {
		log.Fatal(app_err)
	}

}