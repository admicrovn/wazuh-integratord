package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	defaultMaxWorkers           = 20
	defaultWazuhConfigFile      = "/var/ossec/etc/ossec.conf"
	defaultIntegratorConfigFile = "/var/ossec/etc/integrator.conf"
)

type Config struct {
	WazuhConfig      WazuhConfig      `xml:"ossec_config"`
	IntegratorConfig IntegratorConfig `xml:"integrator_config"`
}

type IntegratorConfig struct {
	MaxWorkers int `xml:"max_workers"`
}

type WazuhConfig struct {
	Integrations []Integration `xml:"integration"`
}

type Integration struct {
	Name             string   `xml:"name" json:"name"`
	HookURL          string   `xml:"hook_url" json:"hook_url,omitempty"`
	APIKey           string   `xml:"api_key" json:"api_key,omitempty"`
	Level            int      `xml:"level" json:"level,omitempty"`
	RawRuleID        string   `xml:"rule_id" json:"rule_id,omitempty"`
	RuleIDs          []int    `xml:"-" json:"-"`
	RawGroup         string   `xml:"group" json:"group,omitempty"`
	Groups           []string `xml:"-" json:"-"`
	RawEventLocation string   `xml:"event_location" json:"event_location,omitempty"`
	EventLocations   []string `xml:"-" json:"-"`
	AlertFormat      string   `xml:"alert_format" json:"alert_format,omitempty"`
}

// GetConfig parse ossec.conf then returns config struct
func GetConfig() (*Config, error) {
	wazuhConfFile := defaultWazuhConfigFile
	integratorConfFile := defaultIntegratorConfigFile
	// development
	env := os.Getenv("ENV")
	if env == "dev" {
		wazuhConfFile = "./ossec.conf"
		integratorConfFile = "./integrator.conf"
	}

	// load wazuh config
	wazuhConf, err := os.Open(wazuhConfFile)
	if err != nil {
		return nil, fmt.Errorf("read wazuh config err: %w", err)
	}
	defer wazuhConf.Close()
	data, _ := io.ReadAll(wazuhConf)
	var wazuhConfig WazuhConfig
	err = xml.Unmarshal(data, &wazuhConfig)
	if err != nil {
		return nil, fmt.Errorf("unmarshal err: %w", err)
	}

	// load integrator config
	var integratorConf *os.File
	integratorConf, err = os.Open(integratorConfFile)
	if err != nil {
		return nil, fmt.Errorf("read integrator config err: %w", err)
	}
	defer integratorConf.Close()
	data, _ = io.ReadAll(integratorConf)
	var integratorConfig IntegratorConfig
	err = xml.Unmarshal(data, &integratorConfig)
	if err != nil {
		return nil, fmt.Errorf("unmarshal err: %w", err)
	}

	if check, dup := entryIsDuplicate(wazuhConfig); check {
		return nil, fmt.Errorf("duplicate entry: %s", dup)
	}
	if integratorConfig.MaxWorkers == 0 {
		integratorConfig.MaxWorkers = defaultMaxWorkers
	}
	newIntegrations := make([]Integration, 0)
	for _, integration := range wazuhConfig.Integrations {
		if len(integration.Name) == 0 {
			return nil, errors.New("name can't be empty")
		}
		integrationExecPath := path.Join("/var/ossec/integrations/", integration.Name)
		// development
		if env == "dev" {
			integrationExecPath = "./custom-integration.sh"
		}
		if _, err = os.Stat(integrationExecPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("%s doesn't exist", integrationExecPath)
		}
		if integration.Name != "slack" && integration.Name != "pagerduty" && integration.Name != "virustotal" && !strings.HasPrefix(integration.Name, "custom-") {
			return nil, errors.New("name must be 'slack', 'pagerduty', 'virustotal' or 'custom-'")
		}
		if integration.Level < 1 || integration.Level > 16 {
			return nil, errors.New("level must in range 1-16")
		}
		if integration.RawRuleID != "" {
			ruleIDs := strings.Split(integration.RawRuleID, ",")
			if len(ruleIDs) > 0 {
				for _, sRuleID := range ruleIDs {
					var ruleID int
					ruleID, err = strconv.Atoi(sRuleID)
					if err != nil {
						return nil, errors.New("rule_id must be a number or multiple numbers separated by commas")
					}
					integration.RuleIDs = append(integration.RuleIDs, ruleID)
				}
				integration.RuleIDs = unique(integration.RuleIDs)
			} else {
				var ruleID int
				ruleID, err = strconv.Atoi(integration.RawRuleID)
				if err != nil {
					return nil, errors.New("rule_id must be a number or multiple numbers separated by commas")
				}
				integration.RuleIDs = append(integration.RuleIDs, ruleID)
			}
		}
		if integration.RawGroup != "" {
			groups := strings.Split(integration.RawGroup, ",")
			if len(groups) > 0 {
				integration.Groups = append(integration.Groups, groups...)
			} else {
				integration.Groups = append(integration.Groups, integration.RawGroup)
			}
		}
		if integration.RawEventLocation != "" {
			eventLocations := strings.Split(integration.RawEventLocation, ",")
			if len(eventLocations) > 0 {
				integration.EventLocations = append(integration.EventLocations, eventLocations...)
			} else {
				integration.EventLocations = append(integration.EventLocations, integration.RawEventLocation)
			}
		}
		if integration.AlertFormat != "json" {
			return nil, errors.New("alert_format must be 'json'")
		}
		newIntegrations = append(newIntegrations, integration)
	}
	return &Config{
		WazuhConfig: WazuhConfig{
			Integrations: newIntegrations,
		},
		IntegratorConfig: integratorConfig,
	}, nil
}

func unique(intSlice []int) []int {
	keys := make(map[int]bool)
	var list []int
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func uniqueString(intSlice []string) ([]string, []string) {
	keys := make(map[string]bool)
	var list []string
	var duplicate []string
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		} else {
			duplicate = append(duplicate, entry)
		}
	}
	return list, duplicate
}

func entryIsDuplicate(input WazuhConfig) (bool, string) {
	names := make([]string, 0)
	for _, integration := range input.Integrations {
		names = append(names, integration.Name)
	}
	_, duplicate := uniqueString(names)
	if len(duplicate) > 0 {
		return true, strings.Join(duplicate, " ")
	}
	return false, ""
}
