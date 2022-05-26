import configparser
import time
import json
import urllib3
import requests
import csv
import argparse
from zipfile import ZipFile

parser = argparse.ArgumentParser()
parser.add_argument("email", help="email")
parser.add_argument("password", help="password")
parser.add_argument("ip", help="IP")
args = parser.parse_args()

#config.read("../../config.ini")
IP = args.ip

BASE_URL = "https://" + IP + "/api/ariel/searches"

# We need to pass our Authentication token to the post method.
# Find it at: Console -> Admin -> Authorized Services
#headers = {
#    'SEC': 'cc3201f5-233a-436d-822e-84f07a847491'
#}

# format the url so we can pass the SQL statement
SQL = 'SELECT LOGSOURCENAME(logsourceid) AS "Log Source", LOGSOURCETYPENAME(devicetype) AS "Log Source Type", QIDNAME(qid) AS "Event Name", CATEGORYNAME(category) AS Category, COUNT(*) AS "Number of Events" FROM events GROUP BY "Log Source", "Log Source Type", "Event Name" ORDER BY "Number of Events" DESC LAST 7 DAYS'
url = BASE_URL +"?query_expression=" + SQL

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.post(url, auth=(args.email, args.password), verify=False).json()
#print(json_data)
search_id = json_data['search_id']
#print(json_data.response)

# might not need this timeout between calls, will research more
time.sleep(500)
# format the url so we can pass the search_id to get our results
url = BASE_URL + "/" + search_id + "/" + "results"
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()

# print the resulting json formated data
data2 = json_data

data1 = data2["events"]
csv_columns = ['Log Source', 'Log Source Type', 'Event Name', 'Category', 'Number of Events']

csv_file = "Last7days.csv"
try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")


print("Last7days Data is Generated...\n")


url = "https://" + IP + "/api/config/deployment/hosts"

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()
data1 = json_data


csv_columns = ['eps_rate_hardware_limit', 'appliance', 'components', 'average_fpm', 'public_ip', 'secondary_server_id', 'average_eps', 'cpus', 
'app_memory', 'peak_eps', 'fpm_allocation', 'license_serial_number', 'peak_fpm', 'version', 'private_ip', 'fpm_rate_hardware_limit','hostname',
'total_memory', 'primary_server_id', 'eps_allocation', 'encryption_enabled','id','compression_enabled','status']

csv_file = "siem_architecture_info.csv"
try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")


print("Siem Architecture Data is Generated...\n")




BASE_URL = "https://" + IP + "/api/ariel/searches"

# We need to pass our Authentication token to the post method.
# Find it at: Console -> Admin -> Authorized Services
#headers = {
#    'SEC': 'cc3201f5-233a-436d-822e-84f07a847491'
#}

# format the url so we can pass the SQL statement
SQL = "select sourceip as 'SourceIp' from events where LOGSOURCETYPENAME(deviceType) == 'SIM Generic Log DSM' GROUP BY sourceip last 24 hours"
url = BASE_URL +"?query_expression=" + SQL

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.post(url, auth=(args.email, args.password), verify=False).json()
#print(json_data)
search_id = json_data['search_id']
#print(json_data.response)

# might not need this timeout between calls, will research more
time.sleep(300)

# format the url so we can pass the search_id to get our results
url = BASE_URL + "/" + search_id + "/" + "results"
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()

# print the resulting json formated data
data2 = json_data



data1 = data2["events"]
csv_columns = ['SourceIp']

csv_file = "unknown_events.csv"
try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")



print("Unknown Events Data is Generated...\n")



# format the url so we can pass the SQL statement
SQL1 = "SELECT Hostname, AVG(Value) * 100 AS Disk_Usage, Element FROM events where LOGSOURCENAME(logsourceid) ILIKE '%%health%%' and "
SQL2 = '"Metric ID"'
SQL3 ="='DiskUsage' GROUP BY Hostname, Element ORDER BY Hostname LAST 2 HOURS"

SQL=str(SQL1)+str(SQL2)+str(SQL3)
url = BASE_URL +"?query_expression=" + SQL

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.post(url, auth=(args.email, args.password), verify=False).json()
print(json_data)
search_id = json_data['search_id']
#print(json_data.response)

# might not need this timeout between calls, will research more
time.sleep(300)

# format the url so we can pass the search_id to get our results
url = BASE_URL + "/" + search_id + "/" + "results"
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()

# print the resulting json formated data
data2 = json_data



data1 = data2["events"]
csv_columns = ['Hostname','Disk_Usage','Element']

csv_file = "storage.csv"

try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")



print("Storage Data is Generated...\n")



# format the url so we can pass the SQL statement
SQL1 = 'SELECT Hostname, "Metric ID", AVG(Value) AS Avg_Value, Element FROM events WHERE LOGSOURCENAME(logsourceid) ILIKE '
SQL2 = "'%%health%%'"
SQL3 = ' AND "Metric ID"'
SQL4 = "='SystemCPU' OR" 
SQL5 = ' "Metric ID"'
SQL6 = "='DiskUtilizationDevice' GROUP BY Hostname," 
SQL7 = '"Metric ID", Element ORDER BY Hostname last 20 minutes'

SQL=str(SQL1)+str(SQL2)+str(SQL3)+str(SQL4)+str(SQL5)+str(SQL6)+str(SQL7)
url = BASE_URL +"?query_expression=" + SQL

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.post(url, auth=(args.email, args.password), verify=False).json()
print(json_data)
search_id = json_data['search_id']
#print(json_data.response)

# might not need this timeout between calls, will research more
time.sleep(500)

# format the url so we can pass the search_id to get our results
url = BASE_URL + "/" + search_id + "/" + "results"
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()

# print the resulting json formated data
data2 = json_data



data1 = data2["events"]
csv_columns = ['Hostname','Metric ID','Avg_Value','Element']

csv_file = "cpu_utilization.csv"

try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")



print("CPU Utilization Data is Generated...\n")


url = "https://" + IP + "/api/config/event_sources/log_source_management/log_sources"

# ignore InsecureRequestWarning (Test system)
urllib3.disable_warnings()

# This is a two step process:
# - We pass the SQL statement to the API
# - Retrieve the search_id from the initial rest call
# - We then pass the search_id back to the API to get our results
json_data = requests.get(url, auth=(args.email, args.password), verify=False).json()
data1 = json_data


csv_columns = ['internal', 'protocol_parameters', 'description', 'coalesce_events', 'enabled', 'average_eps', 'group_ids', 'credibility', 
'id', 'store_event_payload', 'target_event_collector_id', 'protocol_type_id', 'language_id', 'creation_date', 'wincollect_external_destination_ids', 'log_source_extension_id','name',
'modified_date', 'auto_discovered', 'type_id', 'last_event_time','requires_deploy','gateway','wincollect_internal_destination_id','status']

csv_file = "log_sources_info.csv"
try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for data in data1:
            writer.writerow(data)
except IOError:
    print("I/O error")


print("Log Sources Information is Generated...\n")






with ZipFile('gap_analysis_data.zip', 'w') as zipObj2:
    zipObj2.write('Last7days.csv')
    zipObj2.write('siem_architecture_info.csv')
    zipObj2.write('unknown_events.csv')
    zipObj2.write('storage.csv')
    zipObj2.write('cpu_utilization.csv')
    zipObj2.write('log_sources_info.csv')


