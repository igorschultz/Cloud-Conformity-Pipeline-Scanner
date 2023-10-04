import os
import sys
import requests
import json
import yaml
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

OUTPUT_FILE = "findings.json"

CC_REGIONS = [
    "us-1",
    "in-1",
    "gb-1",
    "jp-1",
    "de-1",
    "au-1",
    "ca-1",
    "sg-1"
]

RISK_LEVEL_NUMS = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "VERY_HIGH": 3,
    "EXTREME": 4,
}


class CcValidator:
    def __init__(self):

        try:
            logging.info("Obtaining required environment variables...")
            self.cc_region = os.environ["CC_REGION"].lower()

            if self.cc_region not in CC_REGIONS:
                logging.error('Please ensure "CC_REGION" is set to a region which is supported by Conformity')
                sys.exit(1)

            self.api_key = os.environ["CC_API_KEY"]
            self.cfn_template_file_location = os.environ["CFN_TEMPLATE_FILE_LOCATION"]
            risk_level = os.getenv("CC_RISK_LEVEL", "LOW").upper()

        except KeyError:
            logging.error("Please ensure all environment variables are set")
            sys.exit(1)

        try:
            self.offending_risk_level_num = RISK_LEVEL_NUMS[risk_level]

        except KeyError:
            logging.critical("Unknown risk level. Please use one of LOW | MEDIUM | HIGH | VERY_HIGH | EXTREME")
            sys.exit(1)

        logging.info(
            f'All environment variables were received. The pipeline will fail if any "{risk_level}" level '
            f"issues are found"
        )

    def read_template_file(self):
        if not os.path.isfile(self.cfn_template_file_location):
            logging.critical(f"Template file does not exist: {self.cfn_template_file_location}")
            sys.exit(1)

        with open(self.cfn_template_file_location, "r") as f:
            cfn_contents = f.read()

        return cfn_contents

    @staticmethod
    def generate_payload(cfn_template_contents):
        cc_profile_id = os.getenv("CC_PROFILE_ID", "")

        payload = {
            "data": {
                "attributes": {
                    "type": "cloudformation-template",
                    "contents": cfn_template_contents,
                    "profileId": cc_profile_id,
                }
            }
        }

        return payload

    def run_validation(self, payload):
        cfn_scan_endpoint = f"https://conformity.{self.cc_region}.cloudone.trendmicro.com/api/template-scanner/scan"

        json_output = json.dumps(payload, indent=4, sort_keys=True)
        logging.debug(f"Sending the following request:\n{json_output}")

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": "apiKey " + self.api_key,
        }

        resp = requests.post(cfn_scan_endpoint, headers=headers, data=json_output)
        resp_json = json.loads(resp.text)
        json_output = json.dumps(resp_json, indent=4, sort_keys=True)
        logging.debug(f"Received the following response:\n{json_output}")

        message = resp_json.get("Message")
        if message and "deny" in message:
            logging.critical(
                f"{message}. Please ensure you've set the correct Conformity region and that your API key is correct"
            )
            sys.exit(1)

        return resp_json

    def get_results(self, findings):
        offending_entries = []

        if findings.get("errors"):  # pragma: no cover
            logging.critical(findings["errors"])
            sys.exit(1)

        for entry in findings["data"]:
            attributes = entry["attributes"]

            if entry["attributes"]["status"] == "SUCCESS":
                continue

            risk_level_text = attributes["risk-level"]
            risk_level_num = RISK_LEVEL_NUMS[risk_level_text]

            if risk_level_num >= self.offending_risk_level_num:
                offending_entries.append(entry)

        if not offending_entries:
            return offending_entries

        formatted_output = json.dumps(offending_entries, sort_keys=True, indent=4)
        output = formatted_output.replace(r"\"", "")

        with open(OUTPUT_FILE, "w") as f:
            f.write(output)

        return offending_entries

    @staticmethod
    def _check_fail_pipeline(template):
        try:
            fail_pipeline_setting = template["Parameters"]["FailConformityPipeline"]

        except KeyError:
            logging.info(
                'The "FailConformityPipeline" parameter has not been set. The pipeline will fail if the template is '
                "deemed insecure."
            )

            return True

        if fail_pipeline_setting.lower() == "disabled":
            logging.info(
                'The "FailConformityPipeline" parameter has been set to "disabled". The pipeline will not fail even '
                "if the template is deemed insecure."
            )

            return False

        else:
            logging.info(
                'The "FailConformityPipeline" parameter was not set to "disabled". The pipeline will not fail even '
                "if the template is deemed insecure."
            )

            return True

    def _fail_pipeline(self, cfn_template_contents):
        if os.environ.get("FAIL_PIPELINE", "").lower() == "disabled":
            logging.info(
                'The "FAIL_PIPELINE" environment variable is set to "disabled". The pipeline will not fail even if '
                "the template is deemed insecure."
            )
            return False

        # fail pipeline if `FAIL_PIPELINE_CFN` is not set
        if not os.environ.get("FAIL_PIPELINE_CFN", "").lower() == "enabled":
            return True

        logging.info(
            'The "FAIL_PIPELINE_CFN" environment variable is set to "enabled". The template will be checked to see '
            "if the pipeline should fail."
        )

        template_extension = os.path.splitext(self.cfn_template_file_location)[1]

        if template_extension.lower() == ".json":
            dict_template = json.loads(cfn_template_contents)
            fail_pipeline = self._check_fail_pipeline(dict_template)

            return fail_pipeline

        elif template_extension.lower() == ".yaml" or template_extension.lower() == ".yml":
            dict_template = yaml.safe_load(cfn_template_contents)
            fail_pipeline = self._check_fail_pipeline(dict_template)

            return fail_pipeline

        else:
            logging.critical(f"Unknown file extension for template: {template_extension}")
            sys.exit(1)

    def run(self):
        cfn_template_contents = self.read_template_file()
        payload = self.generate_payload(cfn_template_contents)
        findings = self.run_validation(payload)
        offending_entries = self.get_results(findings)

        if not offending_entries:
            logging.info("No offending entries found")
            sys.exit()

        num_offending_entries = len(offending_entries)
        json_offending_entries = json.dumps(offending_entries, indent=4, sort_keys=True)
        logging.info(f"Offending entries:\n{json_offending_entries}")

        fail_pipeline = self._fail_pipeline(cfn_template_contents)

        if fail_pipeline:
            logging.critical(f"{num_offending_entries} offending entries found")
            sys.exit(1)

        else:
            logging.info(
                f"\nPipeline failure has been disabled so the script will exit with a 0 code.\n"
                f"{num_offending_entries} offending entries found."
            )
            sys.exit()


def main():  # pragma: no cover
    cc = CcValidator()
    cc.run()


if __name__ == "__main__":  # pragma: no cover
    main()