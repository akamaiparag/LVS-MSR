import argparse
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import yaml
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from tqdm import tqdm

from .dataframes import parser as dataframes
from .endpoints import apidefinitions, appsec, clientlist, identity


def shared_resources(session, base_url, configuration):
    resources = {
        "configurationDetails": appsec.configuration_details(configuration),
    }

    response = appsec.security_policies(session, base_url, configuration["id"], int(configuration["productionVersion"]))
    if response.status_code == 200:
        resources["securityPolicies"] = response.json()["policies"]

    response = appsec.rate_policies(session, base_url, configuration["id"], int(configuration["productionVersion"]))
    if response.status_code == 200:
        resources["ratePolicies"] = response.json()["ratePolicies"]

    response = appsec.url_protections(session, base_url, configuration["id"], int(configuration["productionVersion"]))
    if response.status_code == 200:
        if "urlProtectionPolicies" in response.json():
            resources["urlProtectionPolicies"] = response.json()["urlProtectionPolicies"]

    response = appsec.reputation_profiles(session, base_url, configuration["id"], int(configuration["productionVersion"]))
    if response.status_code == 200:
        resources["reputationProfiles"] = response.json()["reputationProfiles"]

    return resources


def policies_configuration(session, base_url, security_policy):
    response = appsec.evasive_path_match(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if response.json()["enablePathMatch"]:
            security_policy["Evasive URL Request Matching"] = "On"
        else:
            security_policy["Evasive URL Request Matching"] = "Off"
    else:
        security_policy["Evasive URL Request Matching"] = float("NaN")

    response = appsec.request_body(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if response.json()["requestBodyInspectionLimitInKB"] == "default":
            security_policy["Request Size Inspection Limit (kB)"] = 8
        else:
            security_policy["Request Size Inspection Limit (kB)"] = int(response.json()["requestBodyInspectionLimitInKB"])
    else:
        security_policy["Request Size Inspection Limit (kB)"] = float("NaN")

    response = appsec.logging(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if response.json()["allowSampling"]:
            security_policy["HTTP Header Data Logging"] = "On"
        else:
            security_policy["HTTP Header Data Logging"] = "Off"
    else:
        security_policy["HTTP Header Data Logging"] = float("NaN")

    response = appsec.attack_payload(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if response.json()["enabled"]:
            security_policy["Attack Payload Logging"] = "On"
        else:
            security_policy["Attack Payload Logging"] = "Off"
    else:
        security_policy["Attack Payload Logging"] = float("NaN")

    response = appsec.pragma_header(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if "action" in response.json():
            if response.json()["action"] == "REMOVE":
                security_policy["Strip Pragma Debug Headers"] = "On"
            else:
                security_policy["Strip Pragma Debug Headers"] = "Off"
        else:
            security_policy["Strip Pragma Debug Headers"] = "Off"
    else:
        security_policy["Strip Pragma Debug Headers"] = float("NaN")

    response = appsec.security_controls(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

    if response.status_code == 200:
        if response.json()["policySecurityControls"]["applyNetworkLayerControls"]:
            security_policy["IP/Geo Firewall"] = "On"
        else:
            security_policy["IP/Geo Firewall"] = "Off"

        if response.json()["policySecurityControls"]["applyRateControls"]:
            security_policy["Rate Limiting Policies"] = "On"
        else:
            security_policy["Rate Limiting Policies"] = "Off"

        if response.json()["policySecurityControls"]["applyUrlProtectionControls"]:
            security_policy["URL Protection Rules"] = "On"
        else:
            security_policy["URL Protection Rules"] = "Off"

        if response.json()["policySecurityControls"]["applySlowPostControls"]:
            security_policy["Slow POST Protection"] = "On"
        else:
            security_policy["Slow POST Protection"] = "Not Used"

        if response.json()["policySecurityControls"]["applyApplicationLayerControls"]:
            security_policy["Web Application Firewall"] = "On"
        else:
            security_policy["Web Application Firewall"] = "Off"

        if response.json()["policySecurityControls"]["applyReputationControls"]:
            security_policy["Client Reputation"] = "On"
        else:
            security_policy["Client Reputation"] = "Off"

        if response.json()["policySecurityControls"]["applyBotmanControls"]:
            security_policy["Bot Management"] = "On"
        else:
            security_policy["Bot Management"] = "Off"

    else:
        security_policy["IP/Geo Firewall"] = float("NaN")
        security_policy["Rate Limiting Policies"] = float("NaN")
        security_policy["Slow POST Protection"] = float("NaN")
        security_policy["URL Protection Rules"] = float("NaN")
        security_policy["Web Application Firewall"] = float("NaN")
        security_policy["Client Reputation"] = float("NaN")
        security_policy["Bot Management"] = float("NaN")

    if security_policy["IP/Geo Firewall"] == "On":
        response = appsec.ipgeo_firewall(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            block_exceptions = []

            if response.json()["block"] == "blockSpecificIPGeo":
                security_policy["Firewall Mode"] = "Block List"

                if "ipControls" in response.json():
                    if "blockedIPNetworkLists" in response.json()["ipControls"]:
                        if "networkList" in response.json()["ipControls"]["blockedIPNetworkLists"]:
                            security_policy["Blocked IP Client/Network Lists"] = response.json()["ipControls"]["blockedIPNetworkLists"]["networkList"]
                    if "allowedIPNetworkLists" in response.json()["ipControls"]:
                        if "networkList" in response.json()["ipControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["ipControls"]["allowedIPNetworkLists"]["networkList"])

                if "geoControls" in response.json():
                    if "blockedIPNetworkLists" in response.json()["geoControls"]:
                        if "networkList" in response.json()["geoControls"]["blockedIPNetworkLists"]:
                            security_policy["Blocked Geo Network Lists/Client Lists"] = response.json()["geoControls"]["blockedIPNetworkLists"]["networkList"]
                    if "allowedIPNetworkLists" in response.json()["geoControls"]:
                        if "networkList" in response.json()["geoControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["geoControls"]["allowedIPNetworkLists"]["networkList"])

                if "asnControls" in response.json():
                    if "blockedIPNetworkLists" in response.json()["asnControls"]:
                        if "networkList" in response.json()["asnControls"]["blockedIPNetworkLists"]:
                            security_policy["Blocked ASN Client Lists"] = response.json()["asnControls"]["blockedIPNetworkLists"]["networkList"]
                    if "allowedIPNetworkLists" in response.json()["asnControls"]:
                        if "networkList" in response.json()["asnControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["asnControls"]["allowedIPNetworkLists"]["networkList"])

                if "ukraineGeoControl" in response.json():
                    if "action" in response.json()["ukraineGeoControl"]:
                        if response.json()["ukraineGeoControl"]["action"] == "none":
                            security_policy["Ukraine Disrupted Area"] = "Not Used"
                        else:
                            security_policy["Ukraine Disrupted Area"] = response.json()["ukraineGeoControl"]["action"].title()

                security_policy["Excepted Network Lists/Client Lists"] = block_exceptions

            elif response.json()["block"] == "blockAllTrafficExceptAllowedIPs":
                security_policy["Firewall Mode"] = "Allow List"

                if "ipControls" in response.json():
                    if "allowedIPNetworkLists" in response.json()["ipControls"]:
                        if "networkList" in response.json()["ipControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["ipControls"]["allowedIPNetworkLists"]["networkList"])

                if "geoControls" in response.json():
                    if "allowedIPNetworkLists" in response.json()["geoControls"]:
                        if "networkList" in response.json()["geoControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["geoControls"]["allowedIPNetworkLists"]["networkList"])

                if "asnControls" in response.json():
                    if "allowedIPNetworkLists" in response.json()["asnControls"]:
                        if "networkList" in response.json()["asnControls"]["allowedIPNetworkLists"]:
                            block_exceptions.extend(response.json()["asnControls"]["allowedIPNetworkLists"]["networkList"])

                security_policy["Excepted Network Lists/Client Lists"] = block_exceptions

            else:
                security_policy["Firewall Mode"] = float("NaN")
                security_policy["Blocked IP Client/Network Lists"] = float("NaN")
                security_policy["Blocked Geo Network Lists/Client Lists"] = float("NaN")
                security_policy["Blocked ASN Client Lists"] = float("NaN")
                security_policy["Excepted Network Lists/Client Lists"] = float("NaN")

        else:
            security_policy["Firewall Mode"] = float("NaN")
            security_policy["Blocked IP Client/Network Lists"] = float("NaN")
            security_policy["Blocked Geo Network Lists/Client Lists"] = float("NaN")
            security_policy["Blocked ASN Client Lists"] = float("NaN")
            security_policy["Excepted Network Lists/Client Lists"] = float("NaN")

    if security_policy["Rate Limiting Policies"] == "On":
        response = appsec.rate_policies_action(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            if "ratePolicyActions" in response.json():
                alert = []
                deny = []
                notused = []

                for rate_policy in response.json()["ratePolicyActions"]:
                    if rate_policy["ipv4Action"] == "none":
                        notused.append(rate_policy["id"])
                    elif rate_policy["ipv4Action"] == "alert":
                        alert.append(rate_policy["id"])
                    elif rate_policy["ipv4Action"] == "deny":
                        deny.append(rate_policy["id"])
                    else:
                        deny.append(rate_policy["id"])

                security_policy["Rate Controls in Alert"] = alert
                security_policy["Rate Controls in Deny"] = deny
                security_policy["Not Used Rate Controls"] = notused

    if security_policy["URL Protection Rules"] == "On":
        response = appsec.url_protections_action(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            if "urlProtectionActions" in response.json():
                alert = []
                deny = []
                notused = []

                for url_rule in response.json()["urlProtectionActions"]:
                    if url_rule["action"] == "none":
                        notused.append(url_rule["policyId"])
                    elif url_rule["action"] == "alert":
                        alert.append(url_rule["policyId"])
                    elif url_rule["action"] == "deny":
                        deny.append(url_rule["policyId"])
                    else:
                        deny.append(url_rule["policyId"])

                security_policy["URL Protection Rules in Alert"] = alert
                security_policy["URL Protection Rules in Deny"] = deny
                security_policy["Not Used URL Protection Rules"] = notused

    if security_policy["Slow POST Protection"] == "On":
        response = appsec.slow_post(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            if "action" in response.json():
                security_policy["Slow POST Protection"] = response.json()["action"].title()
            else:
                security_policy["Slow POST Protection"] = "Not Used"

    if security_policy["Web Application Firewall"] == "On":
        response = appsec.waf_mode(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            if response.json()["mode"] == "ASE_AUTO":
                security_policy["Management Mode"] = "Automatic"
            elif response.json()["mode"] == "ASE_MANUAL":
                security_policy["Management Mode"] = "Manual"
            else:
                security_policy["Management Mode"] = "Kona Rule Set"

            if response.json()["mode"] == "ASE_AUTO" or response.json()["mode"] == "ASE_MANUAL":
                security_policy["Latest Update"] = re.search(r"\((.*?)\)", response.json()["current"]).group(1)

                response = appsec.attack_groups(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

                if response.status_code == 200:
                    security_policy["attackGroupActions"] = response.json()["attackGroupActions"]

                response = appsec.penalty_box(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

                if response.status_code == 200:
                    if response.json()["action"] == "none":
                        security_policy["Penalty Box"] = "Not Used"
                    else:
                        security_policy["Penalty Box"] = response.json()["action"].title()

    if security_policy["Client Reputation"] == "On":
        response = appsec.reputation_profiles_action(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            if "reputationProfiles" in response.json():
                alert = []
                deny = []
                notused = []

                for reputation_profile in response.json()["reputationProfiles"]:
                    if reputation_profile["action"] == "none":
                        notused.append(reputation_profile["id"])
                    elif reputation_profile["action"] == "alert":
                        alert.append(reputation_profile["id"])
                    elif reputation_profile["action"] == "deny":
                        deny.append(reputation_profile["id"])
                    else:
                        deny.append(reputation_profile["id"])

                security_policy["Reputation Profiles in Alert"] = alert
                security_policy["Reputation Profiles in Deny"] = deny
                security_policy["Not Used Reputation Profiles"] = notused

    if security_policy["Bot Management"] == "On":
        response = appsec.akamai_bot_actions(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            security_policy["akamaiBots"] = response.json()["actions"]

        response = appsec.bot_detection_actions(session, base_url, security_policy["configId"], security_policy["versionNumber"], security_policy["policyId"])

        if response.status_code == 200:
            security_policy["botDetections"] = response.json()["actions"]

    return security_policy


def main():
    # ARGUMENT PARSING SECTION 
    parser = argparse.ArgumentParser(
        description="Audit Security Policies",
        usage="python3 -m auditsec [-h] account",
        prog="auditsec",
    )

    
    parser.add_argument("account", help="specifies the Akamai Account Name/ID")
    args = parser.parse_args()
    account = args.account

    config_path = Path.cwd() / "config.yaml"
    
    # READ FROM THE config.yaml file. 
    if config_path.exists():
        with open(config_path, "r") as config_file:
            config = yaml.safe_load(config_file)

        EDGERC_DIRECTORY = config.get("EDGERC_DIRECTORY")
        EDGERC_SECTION = config.get("EDGERC_SECTION")
        OUTPUT_DIRECTORY = config.get("OUTPUT_DIRECTORY")

        if EDGERC_DIRECTORY == "default":
            EDGERC_PATH = Path.home() / ".edgerc"
        else:
            EDGERC_PATH = Path(EDGERC_DIRECTORY) / ".edgerc"

    else:
        print("auditsec: error: file_not_found: /Account Audit Tools/config.yaml")
        return

    #Prepare for the call to change to the account we want to run the report for. 
    #We first read the Section in EdgeRC
    #And prepare the Session and base_url variables. We already know the account we want to switch to 
    if EDGERC_PATH.exists():
        edgerc = EdgeRc(EDGERC_PATH)
        base_url = "https://%s" % edgerc.get(EDGERC_SECTION, "host")
        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc, EDGERC_SECTION)
        session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    else:
        print(f"auditsec: error: file_not_found: {EDGERC_PATH}")
        return
    #Switch the identity to the account
    response = identity.account_switch_keys(session, base_url, account)

    if response.status_code == 200:
        if len(response.json()) == 0:
            print(f"auditsec: error: account_not_found: {account}")
            return

        elif len(response.json()) == 1:
            account_switch_key = response.json()[0]["accountSwitchKey"]
            account_name = response.json()[0]["accountName"]

        else:
            for index, item in enumerate(response.json(), start=1):
                print(f"{index}. {item['accountName']}")

            while True:
                choice = input("\nSelect one of the options above: ")

                if choice.isdigit():
                    choice = int(choice)

                    if 1 <= choice <= len(response.json()):
                        print("")

                        account_switch_key = response.json()[choice - 1]["accountSwitchKey"]
                        account_name = response.json()[choice - 1]["accountName"]
                        break

                    else:
                        print(f"\nPlease select a valid option between 1 and {len(response.json())}")

                else:
                    print("\nPlease enter a digit as your selection")

    else:
        print("auditsec: error: invalid_api_access: identity-management")
        return

    session.params = {"accountSwitchKey": account_switch_key}

    #Get all the configurations
    response = appsec.configs(session, base_url)

    if response.status_code == 200:
        configurations = response.json()["configurations"]
        configurations = [item for item in configurations if "productionVersion" in item]

    else:
        print("auditsec: error: invalid_api_access: appsec")
        return

    # Get the hostname coverage
    response = appsec.hostname_coverage(session, base_url)

    if response.status_code == 200:
        hostname_coverage = response.json()["hostnameCoverage"]
    else:
        print("auditsec: error: invalid_api_access: appsec")
        return

    response = clientlist.lists(session, base_url)

    if response.status_code == 200:
        client_lists = {}
        for listId in response.json()["content"]:
            client_lists[listId["listId"]] = listId["name"]

    else:
        print("auditsec: error: invalid_api_access: client-list")
        return

    #this is an important call.
    #Essentially the call is being made to a method "shared_resources" in parallel 5 times with parameters as
    #session, base_url, and each successive value in the configurations collection.
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(shared_resources, [session] * len(configurations), [base_url] * len(configurations), configurations))

    security_policies = []
    rate_limiting_policies = []
    url_protection_policies = []
    client_reputation_profiles = []

    for result in results:
        if "securityPolicies" in result:
            for policy in result["securityPolicies"]:
                policy["configId"] = result["configurationDetails"]["configId"]
                policy["configName"] = result["configurationDetails"]["configName"]
                policy["versionNumber"] = result["configurationDetails"]["versionNumber"]
                security_policies.append(policy)

        if "ratePolicies" in result:
            for policy in result["ratePolicies"]:
                policy["configId"] = result["configurationDetails"]["configId"]
                policy["configName"] = result["configurationDetails"]["configName"]
                policy["versionNumber"] = result["configurationDetails"]["versionNumber"]
                rate_limiting_policies.append(policy)

        if "urlProtectionPolicies" in result:
            for policy in result["urlProtectionPolicies"]:
                policy["configId"] = result["configurationDetails"]["configId"]
                policy["configName"] = result["configurationDetails"]["configName"]
                policy["versionNumber"] = result["configurationDetails"]["versionNumber"]
                url_protection_policies.append(policy)

        if "reputationProfiles" in result:
            for profile in result["reputationProfiles"]:
                profile["configId"] = result["configurationDetails"]["configId"]
                profile["configName"] = result["configurationDetails"]["configName"]
                profile["versionNumber"] = result["configurationDetails"]["versionNumber"]
                client_reputation_profiles.append(profile)

    rate_policies = {}
    for rate_policy in rate_limiting_policies:
        rate_policies[rate_policy["id"]] = rate_policy["name"]

    url_protections = {}
    for url_policy in url_protection_policies:
        url_protections[url_policy["policyId"]] = url_policy["name"]

    reputation_profiles = {}
    for reputation_profile in client_reputation_profiles:
        reputation_profiles[reputation_profile["id"]] = reputation_profile["name"]

    response = apidefinitions.search_operations(session, base_url)

    if response.status_code == 200:
        api_search = response.json()
    else:
        api_search = {
            "apiEndPoints": [],
            "operations": [],
            "resources": [],
        }

    response = appsec.endpoint_coverage(session, base_url)

    if response.status_code == 200:
        endpoint_coverage = response.json()["operations"]
    else:
        endpoint_coverage = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        policy_settings = list(
            tqdm(
                executor.map(policies_configuration, [session] * len(security_policies), [base_url] * len(security_policies), security_policies),
                total=len(security_policies),
                desc=f"{account_name.split('_')[0]}",
            )
        )

    current_year = datetime.now().year

    if OUTPUT_DIRECTORY == "default":
        OUTPUT_DIRECTORY = Path.home() / "Documents" / f"{account_name.split('_')[0]} [{account_switch_key.split(':')[0]}]" / f"{current_year}"
    else:
        OUTPUT_DIRECTORY = Path(OUTPUT_DIRECTORY) / f"{account_name.split('_')[0]} [{account_switch_key.split(':')[0]}]" / f"{current_year}"

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    current_date = datetime.now().strftime("%Y-%m-%d")
    OUTPUT_PATH = OUTPUT_DIRECTORY / f"[{current_date}] [APPSEC] {account_name.split('_')[0]}.xlsx"

    hostname_coverage = dataframes.hostname_coverage(hostname_coverage)
    waf_attackgroups = dataframes.waf_attackgroups(policy_settings)
    #hostname_waf_attackgroups = dataframes.generate_hostname_waf_attackgroups(hostname_coverage, waf_attackgroups)
    hostname_waf_attackgroups = dataframes.generate_merged_dataframe(hostname_coverage,
                                                                   waf_attackgroups,
                                                                   "Security Policies",
                                                                   "Security Policy",
                                                                   "HostNameAndDos")
    dos_protection = dataframes.dos_protection(policy_settings, rate_policies, url_protections)
    hostname_dos_protection = dataframes.generate_merged_dataframe(hostname_coverage,
                                                                   dos_protection,
                                                                   "Security Policies",
                                                                   "Security Policy",
                                                                   "HostNameAndDos")

    advanced_settings = dataframes.advanced_settings(policy_settings)
    ipgeo_firewall = dataframes.ipgeo_firewall(policy_settings, client_lists)


    client_reputation = dataframes.client_reputation(policy_settings, reputation_profiles)
    akamai_bots = dataframes.akamai_bots(policy_settings)
    bot_detections = dataframes.bot_detections(policy_settings)
    hostname_unknown_bot_protection = dataframes.generate_merged_dataframe(hostname_coverage,
                                                                   bot_detections,
                                                                   "Security Policies",
                                                                   "Security Policy",
                                                                   "HostName Unknown Bots")



    endpoint_protection = dataframes.endpoint_protection(endpoint_coverage, api_search)

    writer = pd.ExcelWriter(OUTPUT_PATH, engine="xlsxwriter")
    workbook = writer.book

    #hostname_coverage.to_excel(writer, sheet_name="Hostname Coverage", index=False)
    #advanced_settings.to_excel(writer, sheet_name="Advanced Settings", index=False)
    #ipgeo_firewall.to_excel(writer, sheet_name="IpGeo Firewall", index=False)
    #dos_protection.to_excel(writer, sheet_name="DoS Protection", index=False)
    #waf_attackgroups.to_excel(writer, sheet_name="Web Application Firewall", index=False)

    # Hosts and their WAF Protections
    hostname_waf_attackgroups.to_excel(writer, sheet_name="Host Coverage for WAF", index=False)

    #Hosts and their DOS Protections
    hostname_dos_protection.to_excel(writer, sheet_name="Host Coverage for DOS", index=False)



    if not hostname_unknown_bot_protection.empty:
        # Hosts and their Unknown Bot Protections
        hostname_unknown_bot_protection.to_excel(writer, sheet_name="Host - Unknown Bots", index=False)
    else:
        print("Unknown bots empty")

    if not client_reputation.empty:
        client_reputation.to_excel(writer, sheet_name="Client Reputation", index=False)
    
    if not akamai_bots.empty:
        akamai_bots.to_excel(writer, sheet_name="Known Bots", index=False)

    if not bot_detections.empty:
        bot_detections.to_excel(writer, sheet_name="Unknown Bots", index=False)

    if not endpoint_protection.empty:
        endpoint_protection.to_excel(writer, sheet_name="Endpoint Protection", index=False)

    cell_format = workbook.add_format()
    cell_format.set_align("center")
    cell_format.set_align("vcenter")
    cell_format.set_text_wrap()

    for worksheet in workbook.worksheets():
        worksheet.set_column(0, worksheet.dim_colmax, None, cell_format)
        worksheet.autofilter(0, 0, worksheet.dim_rowmax, worksheet.dim_colmax)
        worksheet.autofit()

    bad_format = workbook.add_format()
    bad_format.set_bg_color("#FFC7CE")
    bad_format.set_border()
    bad_format.set_border_color("#9C0006")

    neutral_format = workbook.add_format()
    neutral_format.set_bg_color("#FEEB9C")
    neutral_format.set_border()
    neutral_format.set_border_color("#9C5700")
    '''
    worksheet = workbook.get_worksheet_by_name("Hostname Coverage")
    worksheet.conditional_format(f"A2:E{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": "=ISBLANK($E2)", "format": bad_format})

    worksheet = workbook.get_worksheet_by_name("Advanced Settings")
    worksheet.conditional_format(f"C2:G{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})

    worksheet = workbook.get_worksheet_by_name("IpGeo Firewall")
    worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})
    worksheet.conditional_format(f"E2:E{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($D2="Block List",$E2="")', "format": neutral_format})
    worksheet.conditional_format(f"F2:F{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($D2="Block List",$F2="")', "format": neutral_format})
    worksheet.conditional_format(f"G2:G{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($D2="Block List",$G2="")', "format": neutral_format})
    worksheet.conditional_format(f"H2:H{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($D2="Block List",$H2="")', "format": neutral_format})
    worksheet.conditional_format(f"I2:I{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Not Used", "format": bad_format})
    worksheet.conditional_format(f"I2:I{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Alert", "format": neutral_format})

    worksheet = workbook.get_worksheet_by_name("DoS Protection")
    worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})
    worksheet.conditional_format(f"D2:D{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($C2="On",NOT($D2=""))', "format": bad_format})
    worksheet.conditional_format(f"H2:H{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=AND($G2="On",NOT($H2=""))', "format": bad_format})
    worksheet.conditional_format(f"K2:K{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Not Used", "format": bad_format})
    worksheet.conditional_format(f"K2:K{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Alert", "format": neutral_format})
    
    worksheet = workbook.get_worksheet_by_name("Web Application Firewall")
    worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})
    worksheet.conditional_format(f"D2:D{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Kona Rule Set", "format": bad_format})
    worksheet.conditional_format(f"D2:D{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Manual", "format": neutral_format})
    worksheet.conditional_format(f"F2:O{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Alert", "format": bad_format})
    worksheet.conditional_format(f"F2:J{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Not Used", "format": bad_format})
    worksheet.conditional_format(f"L2:P{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Not Used", "format": bad_format})
    '''
    if not client_reputation.empty:
        worksheet = workbook.get_worksheet_by_name("Client Reputation")
        worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})
        worksheet.conditional_format(f"D2:D{worksheet.dim_rowmax+1}", {"type": "formula", "criteria": '=SEARCH("high",$D2)', "format": neutral_format})

    if not akamai_bots.empty:
        worksheet = workbook.get_worksheet_by_name("Known Bots")
        worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})

    if not bot_detections.empty:
        worksheet = workbook.get_worksheet_by_name("Unknown Bots")
        worksheet.conditional_format(f"C2:C{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Off", "format": bad_format})
        worksheet.conditional_format(f"D2:N{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Monitor", "format": bad_format})

    if not endpoint_protection.empty:
        worksheet = workbook.get_worksheet_by_name("Endpoint Protection")
        worksheet.conditional_format(f"F2:F{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Monitor", "format": bad_format})
        worksheet.conditional_format(f"G2:G{worksheet.dim_rowmax+1}", {"type": "text", "criteria": "containing", "value": "Monitor", "format": neutral_format})

    workbook.close()


if __name__ == "__main__":
    print("")
    main()
    print("")
