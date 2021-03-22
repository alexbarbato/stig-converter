import csv

responses = []
stig_id_idx = None
comments_idx = None
status_idx = None

# Import CSV
f = open('asd-responses.csv')
csv_responses = csv.reader(f)
for row in csv_responses: 
	responses.append(row)
f.close()

# Check for indexs of mappable fields
for i, title in enumerate(responses[0]):
    if title.lower() == "id":
        stig_id_idx = i
    if title.lower() == "comments":
        comments_idx = i
    if title.lower() == "status":
        status_idx = i

# Import XML
import xml.etree.ElementTree as ET
tree = ET.parse('asd.ckl')
root = tree.getroot()
# Iterate over each vulnerability
for vuln in root.iter('VULN'):
    matching_response = None
    for stig_data in vuln.iter('STIG_DATA'):
        title = stig_data.find('VULN_ATTRIBUTE').text
        if title == 'Vuln_Num':
            # Find the right STIG from the CSV
            vuln_num = stig_data.find('ATTRIBUTE_DATA').text
            matching_response = next(x for x in responses if x[stig_id_idx] == vuln_num)
    
    # Set the updated values should there be a match
    if matching_response:
        comments = vuln.find('COMMENTS')
        comments.text = matching_response[comments_idx]
        status = vuln.find('STATUS')
        if matching_response[status_idx].lower() == 'not a finding':
            status.text = 'NotAFinding'

tree.write('asd-converted.ckl')
        