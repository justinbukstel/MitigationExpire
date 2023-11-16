import requests
import json
from datetime import datetime, timedelta, timezone
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# Veracode API endpoint
url_applications = "https://api.veracode.com/appsec/v1/applications/"
headers = {"User-Agent": "Python HMAC"}

# Make the GET request to get applications
response_applications = requests.get(url_applications, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

# Check if the request was successful (status code 200)
if response_applications.status_code == 200:
    # Parse the JSON response to get application GUIDs
    data_applications = response_applications.json()
    applications = data_applications["_embedded"]["applications"]

    # Iterate through applications
    for app in applications:
        app_name = app["profile"]["name"]
        app_guid = app["guid"]
        print(f"Application Name: {app_name}, Application GUID: {app_guid}")

        # Make the GET request to get findings for each application
        url_findings = f"https://api.veracode.com/appsec/v2/applications/{app_guid}/findings?include_annot=true&scan_type=STATIC"
        response_findings = requests.get(url_findings, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

        # Check if the request was successful (status code 200)
        if response_findings.status_code == 200:
            # Parse the JSON response to get findings
            data_findings = response_findings.json()

            # Check if "_embedded" exists in the response
            if "_embedded" in data_findings:
                # Extract Findings
                findings = data_findings["_embedded"].get("findings", [])

                # List to store issue_ids for rejection
                issue_ids_to_reject = []

                # Iterate through findings
                for finding in findings:
                    issue_id = finding["issue_id"]
                    resolution_status = finding["finding_status"]["resolution_status"]
                    annotations = finding.get("annotations", [])

                    # Check if the resolution_status is "APPROVED" and there are annotations
                    if resolution_status == "APPROVED" and annotations:
                        # Filter only the "APPROVED" annotations
                        approved_annotations = [annot for annot in annotations if annot["action"] == "APPROVED"]

                        # If there are "APPROVED" annotations, get the most recent one
                        if approved_annotations:
                            most_recent_approval = max(approved_annotations, key=lambda x: x["created"])

                            # Get the approval date (make it timezone-aware)
                            approval_date = datetime.fromisoformat(most_recent_approval["created"]).replace(tzinfo=timezone.utc)

                            # Get the current datetime (make it timezone-aware)
                            current_datetime = datetime.now(timezone.utc)

                            # Check if the approval is older than 30 days
                            if current_datetime - approval_date > timedelta(days=1):
                                print(f"Issue ID: {issue_id}, Most recent APPROVED annotation older than 30 days")
                                issue_ids_to_reject.append(str(issue_id))

                # Check if there are issue_ids to reject
                if issue_ids_to_reject:
                    # Create the annotations input JSON
                    annotations_input = {
                        "issue_list": ",".join(issue_ids_to_reject),
                        "comment": "These are older than 30 days",
                        "action": "REJECTED"
                    }

                    # Convert the dictionary to JSON
                    annotations_input_json = json.dumps(annotations_input)

                    # Make the POST request to create annotations
                    url_annotations = f"https://api.veracode.com/appsec/v2/applications/{app_guid}/annotations"
                    headers["Content-Type"] = "application/json"  # Add Content-Type header
                    response_annotations = requests.post(url_annotations, data=annotations_input_json, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

                    # Check if the POST request was successful (status code 200)
                    if response_annotations.status_code == 200:
                        print("Annotations created successfully.")
                    else:
                        print(f"Error creating annotations. Status code: {response_annotations.status_code}")
                        print(response_annotations.text)
                else:
                    print("No issue_ids to reject.")








