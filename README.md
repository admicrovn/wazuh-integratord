# Wazuh Integratord

The [Wazuh Integratord](https://github.com/wazuh/wazuh/tree/master/src/os_integrator) is a daemon that allows Wazuh to
connect to external APIs and alerting tools such as Slack, VirusTotal and PagerDuty.

The original version of `wazuh-integratord` is running in single thread. When there is a large number of alert and the
connections to external APIs are slow, the alerting will be delayed.

This version is written in Go. It was created to help to parse alerts log and alerting faster.

## Configuration

### Wazuh config

`/var/ossec/etc/ossec.conf`

```xml
<ossec_config>

    <integration>
        <name>custom-telegram</name>
        <level>5</level>
        <hook_url>xxx</hook_url>
        <api_key>xxx</api_key>
        <alert_format>json</alert_format>
    </integration>

    <integration>
        <name>custom-login</name>
        <level>3</level>
        <hook_url>xxx</hook_url>
        <api_key>xxx</api_key>
        <rule_id>5715</rule_id>
        <alert_format>json</alert_format>
    </integration>

</ossec_config>
```

### Integrator config

`/var/ossec/etc/integrator.conf`

```xml
<integrator_config>
    <max_workers>20</max_workers>
</integrator_config>
```

* `max_workers` set max number of events process concurrently. Default: `20`
* Other configuration: [https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)

## Build

```
$ go build
```

## Install & Run

Replace original file `/var/ossec/bin/wazuh-integratord` with this binary

```
$ ./wazuh-integratord -h

The Wazuh Integratord is a daemon that allows Wazuh to connect to external APIs and alerting tools such as Slack, VirusTotal and PagerDuty.
This version is written in Go, it was created to help to parse alerts log and alerting faster.

Usage of ./wazuh-integratord:
  -f    Run in foreground mode
  -log-level string
        Log level (default "info")
  -t    Test configuration
```

### Run dev

```
$ ENV=dev ./wazuh-integratord -f
```

### Log level

* Level: `panic` `fatal` `error` `warn` `info` `debug` `trace`
* Default: `info`

## TODO

* Write unit tests