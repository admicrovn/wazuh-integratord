package integrator

import (
	"encoding/json"
	"fmt"
	"github.com/admicrovn/wazuh-integratord/config"
	"github.com/gammazero/workerpool"
	"github.com/masa23/gotail"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAlertsJsonPath   = "/var/ossec/logs/alerts/alerts.json"
	defaultIntegrationsPath = "/var/ossec/integrations"
)

type Event struct {
	Rule     Rule   `json:"rule,omitempty"`
	Location string `json:"location,omitempty"`
}

type Rule struct {
	Level  *int     `json:"level,omitempty"`
	Id     string   `json:"id"`
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
	alertsPath := defaultAlertsJsonPath
	// development
	if os.Getenv("ENV") == "dev" {
		alertsPath = "./alerts.json"
	}
	tail, err := gotail.Open(alertsPath, "")
	if err != nil {
		log.Panic(err)
	}
	// read from the end of file
	tail.InitialReadPositionEnd = true

	var fullEvent string
	retries := 0
	for tail.Scan() {
		line := tail.Text()
		if len(line) > 0 {
			lastChar := line[len(line)-1:]
			if lastChar != "}" {
				fullEvent = fullEvent + line
				continue
			} else {
				if len(fullEvent) > 0 {
					fullEvent = fullEvent + line
				} else {
					fullEvent = line
				}
			}
		}
		log.Debug("sending new alert")
		var event Event
		eventData := []byte(fullEvent)
		err = json.Unmarshal(eventData, &event)
		if err != nil {
			if retries == 0 {
				retries++
				continue
			}
			log.Errorf("unmarshal event err: %s, raw: %s", err, fullEvent)
			// truncate fullEvent
			fullEvent = ""
			// reset retries
			retries = 0
			continue
		}
		// truncate fullEvent
		fullEvent = ""
		// reset retries
		retries = 0
		if len(event.Rule.Id) == 0 {
			log.Trace("skipping: alert doesn't contain rule id")
			continue
		}
		i.wp.Submit(func() {
			for _, integration := range i.config.WazuhConfig.Integrations {
				if len(event.Location) == 0 {
					log.Tracef("[%s] skipping: alert doesn't contain location", integration.Name)
					continue
				}
				if len(integration.EventLocations) > 0 {
					var match bool
					for _, eventLocation := range integration.EventLocations {
						if strings.Contains(event.Location, eventLocation) {
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
					if event.Rule.Level == nil {
						log.Tracef("[%s] skipping: alert doesn't contain rule level", integration.Name)
						continue
					}
					if *event.Rule.Level < *integration.Level {
						log.Tracef("[%s] skipping: alert level is too low", integration.Name)
						continue
					}
				}
				if len(integration.Groups) > 0 {
					var match bool
					for _, integrationGroup := range integration.Groups {
						for _, ruleGroup := range event.Rule.Groups {
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
					var ruleID int
					ruleID, err = strconv.Atoi(event.Rule.Id)
					if err != nil {
						log.Errorf("[%s] alert rule id must be a number", integration.Name)
						continue
					}
					if !contains(integration.RuleIDs, ruleID) {
						log.Tracef("[%s] skipping: rule id doesn't match", integration.Name)
						continue
					}
				}
				var tmpFile string
				tmpFile, err = createTmpAlertFile(integration.Name, eventData)
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

	if err = tail.Err(); err != nil {
		log.Fatalf("Tail %s err: %s", alertsPath, err)
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
	rand.Seed(time.Now().UnixNano())
	randNum := randomInt(100000000, 999999999)
	tmpFile := fmt.Sprintf("/tmp/%s-%d-%d.alert", integrationName, now, randNum)
	err := os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		return "", err
	}
	return tmpFile, nil
}

// executeCommand execute integration command
func executeCommand(integrationName, tempFile, apiKey, hookUrl string) error {
	integrationBin := fmt.Sprintf("%s/%s", defaultIntegrationsPath, integrationName)
	// development
	if os.Getenv("ENV") == "dev" {
		integrationBin = "./custom-integration.sh"
	}
	integrationCmd := exec.Command(integrationBin, tempFile, apiKey, hookUrl)
	log.Debugf("running: %s", integrationCmd.String())
	out, err := integrationCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("err: %s, out: %s", err, out)
	}
	log.Debugf("[%s] command ran successfully", integrationName)
	return nil
}

func randomInt(min, max int) int {
	return min + rand.Intn(max-min)
}

func contains(arr []int, i int) bool {
	for _, v := range arr {
		if v == i {
			return true
		}
	}
	return false
}
