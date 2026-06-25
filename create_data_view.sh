#!/bin/bash
# Creates all Syndicate4 Kibana data views
# Run this ON the Docker host (<server-ip>) or via SSH tunnel

KIBANA="http://localhost:5601"

create_view() {
  local title="$1"
  local name="$2"
  local time_field="$3"
  echo -n "Creating data view '$name' ($title) ... "
  curl -s -X POST "$KIBANA/api/data_views/data_view" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"data_view\":{\"title\":\"$title\",\"name\":\"$name\",\"timeFieldName\":\"$time_field\"}}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK id=' + d.get('data_view',{}).get('id','?')) if 'data_view' in d else print('ERROR: ' + d.get('message','?'))"
}

# 1. Wazuh agent + manager logs (syndicate4-logs-wazuh)
create_view "syndicate4-logs-wazuh" "Wazuh Agent Logs" "@timestamp"

# 2. All syndicate4 logs wildcard
create_view "syndicate4-logs-*" "Syndicate4 All Logs" "@timestamp"

# 3. ML alerts
create_view "syndicate4-ml-alerts" "Syndicate4 ML Alerts" "ml_detected_at"

echo "Done."
