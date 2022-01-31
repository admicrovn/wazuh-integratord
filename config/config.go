package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
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
	HookUrl          *string  `xml:"hook_url" json:"hook_url,omitempty"`
	ApiKey           *string  `xml:"api_key" json:"api_key,omitempty"`
	Level            *int     `xml:"level" json:"level,omitempty"`
	RawRuleId        string   `xml:"rule_id" json:"rule_id,omitempty"`
	RuleIDs          []int    `xml:"-" json:"-"`
	RawGroup         string   `xml:"group" json:"group,omitempty"`
	Groups           []string `xml:"-" json:"-"`
	RawEventLocation *string  `xml:"event_location" json:"event_location,omitempty"`
	EventLocations   []string `xml:"-" json:"-"`
	AlertFormat      *string  `xml:"alert_format" json:"alert_format,omitempty"`
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
		return nil, fmt.Errorf("read wazuh config err: %s", err)
	}
	defer wazuhConf.Close()
	data, _ := io.ReadAll(wazuhConf)
	var wazuhConfig WazuhConfig
	err = xml.Unmarshal(data, &wazuhConfig)
	if err != nil {
		return nil, fmt.Errorf("unmarshal err: %s", err)
	}

	// load integrator config
	var integratorConf *os.File
	integratorConf, err = os.Open(integratorConfFile)
	if err != nil {
		return nil, fmt.Errorf("read integrator config err: %s", err)
	}
	defer integratorConf.Close()
	data, _ = io.ReadAll(integratorConf)
	var integratorConfig IntegratorConfig
	err = xml.Unmarshal(data, &integratorConfig)
	if err != nil {
		return nil, fmt.Errorf("unmarshal err: %s", err)
	}

	if check, dup := entryIsDuplicate(wazuhConfig); check {
		return nil, fmt.Errorf("duplicate entry: %s", dup)
	}
	if integratorConfig.MaxWorkers == 0 {
		integratorConfig.MaxWorkers = defaultMaxWorkers
	}
	var newIntegrations []Integration
	for _, integration := range wazuhConfig.Integrations {
		if len(integration.Name) == 0 {
			return nil, fmt.Errorf("name can't be empty")
		}
		integrationBin := fmt.Sprintf("/var/ossec/integrations/%s", integration.Name)
		// development
		if env == "dev" {
			integrationBin = "./custom-integration.sh"
		}
		if _, err = os.Stat(integrationBin); os.IsNotExist(err) {
			return nil, fmt.Errorf("%s doesn't exist", integrationBin)
		}
		if integration.Name != "slack" && integration.Name != "pagerduty" && integration.Name != "virustotal" && !strings.HasPrefix(integration.Name, "custom-") {
			return nil, fmt.Errorf("name must be 'slack', 'pagerduty', 'virustotal' or 'custom-'")
		}
		if integration.Level != nil {
			if *integration.Level < 0 && *integration.Level > 16 {
				return nil, fmt.Errorf("level must in range 0-16")
			}
		}
		if len(integration.RawRuleId) > 0 {
			ruleIDs := strings.Split(integration.RawRuleId, ",")
			if len(ruleIDs) > 0 {
				for _, sRuleID := range ruleIDs {
					var ruleID int
					ruleID, err = strconv.Atoi(sRuleID)
					if err != nil {
						return nil, fmt.Errorf("rule_id must be a number or multiple numbers separated by commas")
					}
					integration.RuleIDs = append(integration.RuleIDs, ruleID)
				}
				integration.RuleIDs = unique(integration.RuleIDs)
			} else {
				var ruleID int
				ruleID, err = strconv.Atoi(integration.RawRuleId)
				if err != nil {
					return nil, fmt.Errorf("rule_id must be a number or multiple numbers separated by commas")
				}
				integration.RuleIDs = append(integration.RuleIDs, ruleID)
			}
		}
		if len(integration.RawGroup) > 0 {
			groups := strings.Split(integration.RawGroup, ",")
			if len(groups) > 0 {
				for _, group := range groups {
					integration.Groups = append(integration.Groups, group)
				}
			} else {
				integration.Groups = append(integration.Groups, integration.RawGroup)
			}
		}
		if integration.RawEventLocation != nil {
			eventLocations := strings.Split(*integration.RawEventLocation, ",")
			if len(eventLocations) > 0 {
				for _, location := range eventLocations {
					integration.EventLocations = append(integration.EventLocations, location)
				}
			} else {
				integration.EventLocations = append(eventLocations, *integration.RawEventLocation)
			}
		}
		if integration.AlertFormat != nil {
			if *integration.AlertFormat != "json" {
				return nil, fmt.Errorf("alert_format must be 'json'")
			}
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
	var names []string
	for _, integration := range input.Integrations {
		names = append(names, integration.Name)
	}
	_, duplicate := uniqueString(names)
	if len(duplicate) > 0 {
		return true, strings.Join(duplicate, " ")
	}
	return false, ""
}
