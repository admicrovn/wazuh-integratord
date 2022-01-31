package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/admicrovn/wazuh-integratord/config"
	"github.com/admicrovn/wazuh-integratord/integrator"
	"github.com/admicrovn/wazuh-integratord/logger"
	"github.com/fsnotify/fsnotify"
	"github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

const (
	defaultOssecPath = "/var/ossec/"
	defaultPidFile   = "/var/ossec/var/run/wazuh-integratord.pid"
	defaultLogFile   = "/var/ossec/logs/ossec.log"
	defaultUser      = "ossecm"
	appName          = "wazuh-integratord"
)

type Formatter struct {
	TimeFormat string
	LevelDesc  []string
}

func (f *Formatter) Format(entry *log.Entry) ([]byte, error) {
	timestamp := fmt.Sprintf(entry.Time.Format(f.TimeFormat))
	return []byte(fmt.Sprintf("%s %s: %s: %s\n", timestamp, appName, f.LevelDesc[entry.Level], entry.Message)), nil
}

var levelMap = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
}

func getLogLevel(lvl string) (log.Level, error) {
	if level, ok := levelMap[lvl]; ok {
		return level, nil
	}
	return 0, errors.New("invalid log level")
}

func main() {
	logLevel := flag.String("log-level", "info", "Log level")
	testConfig := flag.Bool("t", false, "Test configuration")
	foreground := flag.Bool("f", false, "Run in foreground mode")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nThe Wazuh Integratord is a daemon that allows "+
			"Wazuh to connect to external APIs and alerting tools such as Slack, VirusTotal and PagerDuty.\n"+
			"This version is written in Go, it was created to help to parse alerts log and alerting faster.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	logFormat := new(Formatter)
	logFormat.TimeFormat = "2006/01/02 15:04:05"
	logFormat.LevelDesc = []string{"PANIC", "FATAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}
	log.SetFormatter(logFormat)
	level, err := getLogLevel(*logLevel)
	if err != nil {
		log.Fatalf("invalid log level. must be one of: panic, fatal, error, warn, info, debug, trace")
	}
	log.SetLevel(level)
	var cfg *config.Config
	cfg, err = config.GetConfig()
	if err != nil {
		log.Fatalf("config err: %s", err)
	}
	if *testConfig {
		fmt.Println("Configuration file is valid")
		return
	}
	if !*foreground {
		pidFile := defaultPidFile
		logFile := defaultLogFile
		ossecPath := defaultOssecPath
		var cred *syscall.Credential
		// development
		if os.Getenv("ENV") == "dev" {
			pidFile = "./wazuh-integratord.pid"
			logFile = "./ossec.log"
			ossecPath = "./"
		} else {
			var u *user.User
			u, err = user.Lookup(defaultUser)
			if err != nil {
				log.Fatalf("get uid err: %s", err)
			}
			uid, _ := strconv.ParseUint(u.Uid, 10, 32)
			gid, _ := strconv.ParseUint(u.Gid, 10, 32)
			cred = &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			}
		}
		cntxt := &daemon.Context{
			PidFileName: pidFile,
			PidFilePerm: 0644,
			LogFileName: logFile,
			LogFilePerm: 0660,
			WorkDir:     ossecPath,
			Credential:  cred,
			Umask:       027,
		}
		var d *os.Process
		d, err = cntxt.Reborn()
		if err != nil {
			log.Fatalf("unable to run: %s", err)
		}
		if d != nil {
			return
		}
		defer cntxt.Release()
		go setupLog(logFile)
	}
	i := integrator.New(cfg)
	go i.Stats()
	go i.RunIntegratorSocketServer()
	i.Run()
}

func setupLog(logFile string) {
	lf, err := logger.NewLogFile(logFile, os.Stderr)
	if err != nil {
		log.Fatalf("unable to setup log file: %s", err.Error())
	}
	log.SetOutput(lf)

	var watcher *fsnotify.Watcher
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Rename == fsnotify.Rename {
					log.Infof("log rotated: %s", event.Name)
					if err = lf.Rotate(); err != nil {
						log.Fatalf("unable to rotate log: %s", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("watch err: %s", err)
			}
		}
	}()
	err = watcher.Add(logFile)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
