# wazuh-repo
Custom collection of different things around Wazuh

## Teams Integration Installation
To use the Teams Integration simply add `custom-teams` and `custom-teams.py` into `/var/ossec/integrations/`.

Afterwards you need to set the proper permissions and also add a new file:
```bash
touch /var/ossec/logs/custom-teams.py.log
chown wazuh:wazuh /var/ossec/logs/custom-teams.py.log
chown wazuh:wazuh /var/ossec/integrations/custom-teams*

chmod +x /var/ossec/integrations/custom-teams*
```
Inside `/var/ossec/etc/ossec.conf` add following node:
```xml
<integration>
  <name>custom-teams</name>
  <level>14</level>
  <hook_url>PowerAutomateURL</hook_url>
  <alert_format>json</alert_format>
</integration>
```
This will send an alert via PowerAutomate if the level is 14 or higher. To change the filter see [Wazuh Documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html#optional-filters)