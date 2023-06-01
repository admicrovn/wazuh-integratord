package integrator

import (
	"fmt"
	"github.com/admicrovn/wazuh-integratord/config"
	"github.com/gammazero/workerpool"
	"github.com/goccy/go-json"
	"github.com/grafana/tail"
	log "github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAlertsJSONPath   = "/var/ossec/logs/alerts/alerts.json"
	defaultIntegrationsPath = "/var/ossec/integrations"
	DEV                     = "dev"
)

type Alert struct {
	Rule     Rule   `json:"rule,omitempty"`
	Location string `json:"location,omitempty"`
}

type Rule struct {
	Level  *int     `json:"level,omitempty"`
	ID     string   `json:"id"`
	Groups []string `json:"groups,omitempty"`
}

type Integrator struct {
	config *config.Config
	wp     *workerpool.WorkerPool
}

// New creates integrator instance
func New(cfg *config.Config) *Integrator {
	wp := workerpool.New(cfg.IntegratorConfig.MaxWorkers)
	return &Integrator{
		config: cfg,
		wp:     wp,
	}
}

// Run parsing alerts.json file.
// if an alert is match with conditions then execute integration command
func (i *Integrator) Run() {
	for _, integration := range i.config.WazuhConfig.Integrations {
		log.Infof("enabling integration for: '%s'", integration.Name)
	}
	alertsJSONPath := defaultAlertsJSONPath
	// development
	if os.Getenv("ENV") == DEV {
		alertsJSONPath = "./alerts.json"
	}

	t, err := tail.TailFile(alertsJSONPath, tail.Config{
		Logger: log.StandardLogger(),
		Follow: true,
		ReOpen: true,
		Poll:   true,
		Location: &tail.SeekInfo{
			Whence: io.SeekEnd,
		},
	})
	if err != nil {
		log.Fatalf("failed to tail file: %s", err.Error())
	}

	ch := make(chan string)
	go i.handleAlert(ch)

	var fullEvent string
	for line := range t.Lines {
		text := line.Text
		if strings.HasPrefix(text, "{\"timestamp\"") && strings.HasSuffix(text, "}") {
			ch <- text
			continue
		}
		fullEvent += text
		continue
	}
}

// Stats print number of alerts in the waiting queue every 10s
func (i *Integrator) Stats() {
	for {
		time.Sleep(10 * time.Second)
		waitingQueueSize := i.wp.WaitingQueueSize()
		log.Infof("alerts_in_waiting_queue: %d", waitingQueueSize)
	}
}

// createTmpAlertFile create temp file for alert
func createTmpAlertFile(integrationName string, data []byte) (string, error) {
	now := time.Now().Unix()
	randNum := rand.Int() //nolint:gosec
	tmpFile := fmt.Sprintf("/tmp/%s-%d-%d.alert", integrationName, now, randNum)
	err := os.WriteFile(tmpFile, data, 0644) //nolint:gosec
	if err != nil {
		return "", err
	}
	return tmpFile, nil
}

// executeCommand execute integration command
func executeCommand(integrationName, tempFile, apiKey, hookURL string) error {
	integrationBin := fmt.Sprintf("%s/%s", defaultIntegrationsPath, integrationName)
	// development
	if os.Getenv("ENV") == DEV {
		integrationBin = "./custom-integration.sh"
	}
	integrationCmd := exec.Command(integrationBin, tempFile, apiKey, hookURL)
	log.Debugf("running: %s", integrationCmd.String())
	out, err := integrationCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("err: %w, out: %s", err, out)
	}
	log.Debugf("[%s] command ran successfully", integrationName)
	return nil
}

func contains(arr []int, i int) bool {
	for _, v := range arr {
		if v == i {
			return true
		}
	}
	return false
}

// handleAlert parse alert json
func (i *Integrator) handleAlert(c chan string) {
	for {
		s := <-c
		log.Debug("sending new alert")
		var alert Alert
		err := json.Unmarshal([]byte(s), &alert)
		if err != nil {
			log.Errorf("unmarshal event err: %s, raw: %s", err, s)
			continue
		}
		if len(alert.Rule.ID) == 0 {
			log.Trace("skipping: alert doesn't contain rule id")
			continue
		}
		log.Trace(s)
		i.parseAlertAndRunIntegration(s, alert)
	}
}

func (i *Integrator) parseAlertAndRunIntegration(s string, alert Alert) {
	i.wp.Submit(func() {
		for _, integration := range i.config.WazuhConfig.Integrations {
			if len(alert.Location) == 0 {
				log.Tracef("[%s] skipping: alert doesn't contain location", integration.Name)
				continue
			}
			if len(integration.EventLocations) > 0 {
				var match bool
				for _, eventLocation := range integration.EventLocations {
					if strings.Contains(alert.Location, eventLocation) {
						match = true
						break
					}
				}
				if !match {
					log.Tracef("[%s] skipping: location doesn't match", integration.Name)
					continue
				}
			}
			if integration.Level != nil {
				if alert.Rule.Level == nil {
					log.Tracef("[%s] skipping: alert doesn't contain rule level", integration.Name)
					continue
				}
				if *alert.Rule.Level < *integration.Level {
					log.Tracef("[%s] skipping: alert level is too low", integration.Name)
					continue
				}
			}
			if len(integration.Groups) > 0 {
				var match bool
				for _, integrationGroup := range integration.Groups {
					for _, ruleGroup := range alert.Rule.Groups {
						if integrationGroup == ruleGroup {
							match = true
							break
						}
					}
					if match {
						break
					}
				}
				if !match {
					log.Tracef("[%s] skipping: group doesn't match", integration.Name)
					continue
				}
			}
			if len(integration.RuleIDs) > 0 {
				ruleID, err := strconv.Atoi(alert.Rule.ID)
				if err != nil {
					log.Errorf("[%s] alert rule id must be a number", integration.Name)
					continue
				}
				if !contains(integration.RuleIDs, ruleID) {
					log.Tracef("[%s] skipping: rule id doesn't match", integration.Name)
					continue
				}
			}
			tmpFile, err := createTmpAlertFile(integration.Name, []byte(s))
			if err != nil {
				log.Errorf("[%s] create tmp file err: %s", integration.Name, err)
				goto CleanUp
			}
			// execute integration command
			err = executeCommand(integration.Name, tmpFile, *integration.ApiKey, *integration.HookUrl)
			if err != nil {
				log.Errorf("[%s] exec integration command err: %s", integration.Name, err)
			}
			goto CleanUp
		CleanUp:
			// remove tmp file
			err = os.Remove(tmpFile)
			if err != nil {
				log.Errorf("[%s] remove tmp file err: %s", integration.Name, err)
				continue
			}
		}
	})
}
