# Option A: Full working approach (Manager-side enrichment)

1. Create an Active Response script on the manager

       nano /var/ossec/active-response/bin/ollama_enrich.sh

       sudo chmod 750 /var/ossec/active-response/bin/usb_ollama_enrich.sh
       sudo chown root:wazuh /var/ossec/active-response/bin/usb_ollama_enrich.sh


2. Add the command + active response in manager ossec.conf

       <ossec_config>
       <localfile>
        <log_format>syslog</log_format>
        <location>/var/ossec/logs/seceoknight-enrich.log</location>
       </localfile>

       <command>
        <name>usb_ollama_enrich</name>
        <executable>usb_ollama_enrich.sh</executable>
        <timeout_allowed>no</timeout_allowed>
       </command>

       <active-response>
        <disabled>no</disabled>
        <command>usb_ollama_enrich</command>
        <location>server</location>
        <rules_id>111000</rules_id>
       </active-response>
       </ossec_config>

Put your list of rule IDs above active response which you want to enrich.

3. Add a decoder for the enrichment output

       nano /var/ossec/etc/decoders/local_decoder.xml

Decoders:

    <decoder name="SeceoKnight_enrich_decoder">
      <prematch>^SeceoKnight-ENRICH:</prematch>
    </decoder>

    <decoder name="SeceoKnight_enrich_child">
      <parent>SeceoKnight_enrich_decoder</parent>
      <regex type="pcre2">base_rule_id=(\d+)\sagent=([^\s]+)\sip=([^\s]+).*\|\sseceoknight_response:\s(.*)$</regex>
      <order>enrich.base_rule_id, enrich.agent, enrich.ip, enrich.seceoknight_response</order>
    </decoder>

4. Add a rule to display it nicely

       nano /var/ossec/etc/rules/local_rules.xml

rule:

    <group name="seceoknight-enrich,">
      <rule id="209111" level="10">
        <decoded_as>SeceoKnight_enrich_decoder</decoded_as>
        <description>USB alert enrichment (rule $(enrich.base_rule_id)) on $(enrich.agent): $(enrich.seceoknight_response)</description>
      </rule>
    </group>


5. Create it and set perms:

       sudo touch /var/ossec/logs/seceoknight-enrich.log
       sudo chmod 640 /var/ossec/logs/seceoknight-enrich.log
       sudo chown root:wazuh /var/ossec/logs/seceoknight-enrich.log 2>/dev/null || true


