import requests
import json
from datetime import datetime, timedelta, timezone
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# Veracode API endpoints
url_applications_static = "https://api.veracode.com/appsec/v1/applications/"
url_applications_sca_annotations = "https://api.veracode.com/srcclr/v3/applications/{}/sca_annotations"
headers = {"User-Agent": "Python HMAC"}

# Set Days Threshold for the number of days
days_threshold = 0

# Function to create SCA annotations
def create_sca_annotations(app_guid, component_id, cve_name, comment):
    # Define the annotations input for SCA
    annotations_input_sca = {
        "action": "REJECT",
        "comment": comment,
        "annotation_type": "VULNERABILITY",
        "annotations": [
            {
                "component_id": component_id,
                "cve_name": cve_name
            }
        ]
    }

    # Convert the dictionary to JSON for SCA
    annotations_input_json_sca = json.dumps(annotations_input_sca)

    # Make the POST request to create SCA annotations
    url_annotations_sca = f"https://api.veracode.com/srcclr/v3/applications/{app_guid}/sca_annotations"
    headers["Content-Type"] = "application/json"  # Add Content-Type header
    response_annotations_sca = requests.post(url_annotations_sca, data=annotations_input_json_sca, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

    # Check if the POST request was successful for SCA
    if response_annotations_sca.status_code == 200:
        print("SCA Annotations created successfully.")
    else:
        print(f"Error creating SCA annotations. Status code: {response_annotations_sca.status_code}")
        print(response_annotations_sca.text)

# Make the GET request to get Static applications
response_applications_static = requests.get(url_applications_static, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

# Check if the request was successful for Static (status code 200)
if response_applications_static.status_code == 200:
    # Parse the JSON response to get Static applications
    data_applications_static = response_applications_static.json()
    applications_static = data_applications_static["_embedded"]["applications"]

    # Flag to check if any applications have findings to reject
    found_findings = False

    # Set to keep track of processed applications
    processed_apps = set()

    # Iterate through applications (Static)
    for app_static in applications_static:
        app_name_static = app_static["profile"]["name"]
        app_guid_static = app_static["guid"]

        # Skip processing if the application is already processed
        if app_guid_static in processed_apps:
            continue

        # Initialize flags for Static and SCA findings
        static_findings_present = False
        sca_findings_present = False

        # Make the GET request to get findings for each application (Static)
        url_findings_static = f"https://api.veracode.com/appsec/v2/applications/{app_guid_static}/findings?include_annot=true&scan_type=STATIC"
        response_findings_static = requests.get(url_findings_static, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

        # Check if the request was successful for Static (status code 200)
        if response_findings_static.status_code == 200:
            # Parse the JSON response to get findings (Static)
            data_findings_static = response_findings_static.json()

            # List to store issue_ids for rejection (Static)
            issue_ids_to_reject_static = []

            # Iterate through findings (Static)
            if "_embedded" in data_findings_static:
                findings_static = data_findings_static["_embedded"].get("findings", [])

                # Iterate through static findings
                for finding_static in findings_static:
                    issue_id_static = finding_static["issue_id"]
                    resolution_status_static = finding_static["finding_status"]["resolution_status"]
                    annotations_static = finding_static.get("annotations", [])

                    # Check if the resolution_status is "APPROVED" and there are annotations
                    if resolution_status_static == "APPROVED" and annotations_static:
                        # Filter only the "APPROVED" annotations
                        approved_annotations_static = [annot for annot in annotations_static if annot["action"] == "APPROVED"]

                        # If there are "APPROVED" annotations, get the most recent one
                        if approved_annotations_static:
                            most_recent_approval_static = max(approved_annotations_static, key=lambda x: x["created"])

                            # Get the approval date (make it timezone-aware)
                            approval_date_static = datetime.fromisoformat(most_recent_approval_static["created"]).replace(tzinfo=timezone.utc)

                            # Get the current datetime (make it timezone-aware)
                            current_datetime_static = datetime.now(timezone.utc)

                            # Check if the approval is older than 30 days
                            if current_datetime_static - approval_date_static > timedelta(days=days_threshold):
                                # Print Static Application Name only if not already printed
                                if not static_findings_present:
                                    print(f"\nStatic Application Name: {app_name_static}, Application GUID: {app_guid_static}")
                                    static_findings_present = True

                                print(f"Static Issue ID: {issue_id_static}, Most recent APPROVED annotation older than 30 days")
                                issue_ids_to_reject_static.append(str(issue_id_static))

                # Check if there are issue_ids to reject (Static)
                if issue_ids_to_reject_static:
                    # Create the annotations input JSON (Static)
                    annotations_input_static = {
                        "issue_list": ",".join(issue_ids_to_reject_static),
                        "comment": "These have expired",
                        "action": "REJECTED"
                    }

                    # Convert the dictionary to JSON (Static)
                    annotations_input_json_static = json.dumps(annotations_input_static)

                    # Make the POST request to create annotations (Static)
                    url_annotations_static = f"https://api.veracode.com/appsec/v2/applications/{app_guid_static}/annotations"
                    headers["Content-Type"] = "application/json"  # Add Content-Type header
                    response_annotations_static = requests.post(url_annotations_static, data=annotations_input_json_static, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

                    # Check if the POST request was successful for Static (status code 200)
                    if response_annotations_static.status_code == 200:
                        print("Static Annotations created successfully.")
                        found_findings = True
                    else:
                        print(f"Error creating Static annotations. Status code: {response_annotations_static.status_code}")
                        print(response_annotations_static.text)
                else:
                    pass  # No need to print "No Static issue_ids to reject."

            # Omitted the message if no findings were present
        else:
            print(f"Error getting Static findings. Status code: {response_findings_static.status_code}")
            print(response_findings_static.text)

        # Make the GET request to get SCA annotations for each application
        response_sca_annotations = requests.get(url_applications_sca_annotations.format(app_guid_static), auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)

        # Check if the request was successful for SCA (status code 200)
        if response_sca_annotations.status_code == 200:
            # Parse the JSON response to get SCA annotations
            data_sca_annotations = response_sca_annotations.json()

            # Check if "approved_annotations" exists in the response
            if "approved_annotations" in data_sca_annotations:
                approved_annotations_sca = data_sca_annotations["approved_annotations"]

                # List to store component_id and cve_name for rejection
                sca_findings_to_reject = []

                # Iterate through approved SCA annotations
                for annotation_sca in approved_annotations_sca:
                    annotation_ts = annotation_sca["history"][0]["annotation_ts"]
                    approval_date_sca = datetime.fromisoformat(annotation_ts).replace(tzinfo=timezone.utc)
                    current_datetime_sca = datetime.now(timezone.utc)

                    # Check if the approval is older than 30 days
                    if current_datetime_sca - approval_date_sca > timedelta(days=days_threshold):
                        component_id_sca = annotation_sca["component"]["id"]
                        cve_name_sca = annotation_sca["vulnerability"]["cve_name"]
                        comment_sca = annotation_sca["latest_comment"]
                        sca_findings_to_reject.append((component_id_sca, cve_name_sca, comment_sca))
                        found_findings = True
                        sca_findings_present = True

                # Check if there are SCA findings to reject
                if sca_findings_to_reject:
                    # Print SCA Application Name only if not already printed
                    if not sca_findings_present:
                        print(f"\nSCA Application Name: {app_name_static}, Application GUID: {app_guid_static}")
                        sca_findings_present = True

                    # Iterate through SCA findings to create annotations
                    for component_id_sca, cve_name_sca, comment_sca in sca_findings_to_reject:
                        print(f"SCA CVE ID: {cve_name_sca}, Most recent APPROVED annotation older than 30 days")
                        create_sca_annotations(app_guid_static, component_id_sca, cve_name_sca, comment_sca)

                    # Mark the application as processed
                    processed_apps.add(app_guid_static)

                else:
                    pass  # No need to print "No SCA findings to reject."

            else:
                pass  # No need to print "No approved SCA annotations."

        else:
            print(f"Error getting SCA annotations. Status code: {response_sca_annotations.status_code}")
            print(response_sca_annotations.text)

        # Display a message based on whether any applications have findings to reject
        if found_findings:
            print("\n")  # Add space between applications
        else:
            pass  # No need to print "No applications have findings to reject."

    # Display a final message if no more applications have findings to reject
    print("No more applications have findings to reject.")

else:
    print(f"Error getting Static applications. Status code: {response_applications_static.status_code}")
    print(response_applications_static.text)








