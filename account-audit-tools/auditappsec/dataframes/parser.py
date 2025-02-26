import pandas as pd


def hostname_coverage(hostnames):
    for hostname in hostnames:
        hostname["Hostname"] = hostname["hostname"]

        if hostname["status"] == "covered":
            hostname["Status"] = "Covered"
        elif hostname["status"] == "not_covered":
            hostname["Status"] = "Not Covered"
        else:
            hostname["Status"] = float("NaN")

        if "configuration" in hostname:
            hostname["Security Configuration"] = hostname["configuration"]["name"]

        if hostname["hasMatchTarget"]:
            hostname["Has Match Target"] = "Yes"
        else:
            hostname["Has Match Target"] = "No"

        if "policyNames" in hostname:
            hostname["Security Policies"] = "\n".join(hostname["policyNames"])

    df1 = pd.DataFrame(hostnames)
    df1 = df1[
        [
            "Hostname",
            "Status",
            "Security Configuration",
            "Has Match Target",
            "Security Policies",
        ]
    ]

    return df1


def advanced_settings(
    policy_settings,
):
    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]
    df1 = df1[
        [
            "Security Policy",
            "Security Configuration",
            "Evasive URL Request Matching",
            "Request Size Inspection Limit (kB)",
            "HTTP Header Data Logging",
            "Attack Payload Logging",
            "Strip Pragma Debug Headers",
        ]
    ]

    return df1


def ipgeo_firewall(policy_settings, client_lists):
    for policy in policy_settings:
        if "Blocked IP Client/Network Lists" in policy:
            for i in range(len(policy["Blocked IP Client/Network Lists"])):
                if policy["Blocked IP Client/Network Lists"][i] in client_lists:
                    policy["Blocked IP Client/Network Lists"][i] = f"{client_lists[policy['Blocked IP Client/Network Lists'][i]]} [{policy['Blocked IP Client/Network Lists'][i]}]"
            policy["Blocked IP Client/Network Lists"] = "\n".join(policy["Blocked IP Client/Network Lists"])
        else:
            policy["Blocked IP Client/Network Lists"] = float("NaN")

        if "Blocked Geo Network Lists/Client Lists" in policy:
            for i in range(len(policy["Blocked Geo Network Lists/Client Lists"])):
                if policy["Blocked Geo Network Lists/Client Lists"][i] in client_lists:
                    policy["Blocked Geo Network Lists/Client Lists"][i] = (
                        f"{client_lists[policy['Blocked Geo Network Lists/Client Lists'][i]]} [{policy['Blocked Geo Network Lists/Client Lists'][i]}]"
                    )
            policy["Blocked Geo Network Lists/Client Lists"] = "\n".join(policy["Blocked Geo Network Lists/Client Lists"])
        else:
            policy["Blocked Geo Network Lists/Client Lists"] = float("NaN")

        if "Blocked ASN Client Lists" in policy:
            for i in range(len(policy["Blocked ASN Client Lists"])):
                if policy["Blocked ASN Client Lists"][i] in client_lists:
                    policy["Blocked ASN Client Lists"][i] = f"{client_lists[policy['Blocked ASN Client Lists'][i]]} [{policy['Blocked ASN Client Lists'][i]}]"
            policy["Blocked ASN Client Lists"] = "\n".join(policy["Blocked ASN Client Lists"])
        else:
            policy["Blocked ASN Client Lists"] = float("NaN")

        if "Excepted Network Lists/Client Lists" in policy:
            for i in range(len(policy["Excepted Network Lists/Client Lists"])):
                if policy["Excepted Network Lists/Client Lists"][i] in client_lists:
                    policy["Excepted Network Lists/Client Lists"][i] = (
                        f"{client_lists[policy['Excepted Network Lists/Client Lists'][i]]} [{policy['Excepted Network Lists/Client Lists'][i]}]"
                    )
            policy["Excepted Network Lists/Client Lists"] = "\n".join(policy["Excepted Network Lists/Client Lists"])
        else:
            policy["Excepted Network Lists/Client Lists"] = float("NaN")

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]
    df1 = df1[
        [
            "Security Policy",
            "Security Configuration",
            "IP/Geo Firewall",
            "Firewall Mode",
            "Blocked IP Client/Network Lists",
            "Blocked Geo Network Lists/Client Lists",
            "Blocked ASN Client Lists",
            "Excepted Network Lists/Client Lists",
            "Ukraine Disrupted Area",
        ]
    ]

    return df1


def dos_protection(policy_settings, rate_policies, url_protections):
    for policy in policy_settings:
        if "Rate Controls in Alert" in policy:
            for i in range(len(policy["Rate Controls in Alert"])):
                policy["Rate Controls in Alert"][i] = f"{rate_policies[policy['Rate Controls in Alert'][i]]} [{policy['Rate Controls in Alert'][i]}]"
            policy["Rate Controls in Alert"] = "\n".join(policy["Rate Controls in Alert"])
        else:
            policy["Rate Controls in Alert"] = float("NaN")

        if "Rate Controls in Deny" in policy:
            for i in range(len(policy["Rate Controls in Deny"])):
                policy["Rate Controls in Deny"][i] = f"{rate_policies[policy['Rate Controls in Deny'][i]]} [{policy['Rate Controls in Deny'][i]}]"
            policy["Rate Controls in Deny"] = "\n".join(policy["Rate Controls in Deny"])
        else:
            policy["Rate Controls in Deny"] = float("NaN")

        if "Not Used Rate Controls" in policy:
            for i in range(len(policy["Not Used Rate Controls"])):
                policy["Not Used Rate Controls"][i] = f"{rate_policies[policy['Not Used Rate Controls'][i]]} [{policy['Not Used Rate Controls'][i]}]"
            policy["Not Used Rate Controls"] = "\n".join(policy["Not Used Rate Controls"])
        else:
            policy["Not Used Rate Controls"] = float("NaN")

        if "URL Protection Rules in Alert" in policy:
            for i in range(len(policy["URL Protection Rules in Alert"])):
                policy["URL Protection Rules in Alert"][i] = f"{url_protections[policy['URL Protection Rules in Alert'][i]]} [{policy['URL Protection Rules in Alert'][i]}]"
            policy["URL Protection Rules in Alert"] = "\n".join(policy["URL Protection Rules in Alert"])
        else:
            policy["URL Protection Rules in Alert"] = float("NaN")

        if "URL Protection Rules in Deny" in policy:
            for i in range(len(policy["URL Protection Rules in Deny"])):
                policy["URL Protection Rules in Deny"][i] = f"{url_protections[policy['URL Protection Rules in Deny'][i]]} [{policy['URL Protection Rules in Deny'][i]}]"
            policy["URL Protection Rules in Deny"] = "\n".join(policy["URL Protection Rules in Deny"])
        else:
            policy["URL Protection Rules in Deny"] = float("NaN")

        if "Not Used URL Protection Rules" in policy:
            for i in range(len(policy["Not Used URL Protection Rules"])):
                policy["Not Used URL Protection Rules"][i] = f"{url_protections[policy['Not Used URL Protection Rules'][i]]} [{policy['Not Used URL Protection Rules'][i]}]"
            policy["Not Used URL Protection Rules"] = "\n".join(policy["Not Used URL Protection Rules"])
        else:
            policy["Not Used URL Protection Rules"] = float("NaN")

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]
    df1 = df1[
        [
            "Security Policy",
            "Security Configuration",
            "Rate Limiting Policies",
            "Rate Controls in Alert",
            "Rate Controls in Deny",
            "Not Used Rate Controls",
            "URL Protection Rules",
            "URL Protection Rules in Alert",
            "URL Protection Rules in Deny",
            "Not Used URL Protection Rules",
            "Slow POST Protection",
        ]
    ]

    return df1


def waf_attackgroups(policy_settings):
    for policy in policy_settings:
        if "attackGroupActions" in policy:
            for attack_group in policy["attackGroupActions"]:
                match attack_group["group"]:
                    case "CMD":
                        if attack_group["action"] == "none":
                            policy["Command Injection"] = "Not Used"
                        else:
                            policy["Command Injection"] = attack_group["action"].title()

                    case "XSS":
                        if attack_group["action"] == "none":
                            policy["Cross Site Scripting"] = "Not Used"
                        else:
                            policy["Cross Site Scripting"] = attack_group["action"].title()

                    case "LFI":
                        if attack_group["action"] == "none":
                            policy["Local File Inclusion"] = "Not Used"
                        else:
                            policy["Local File Inclusion"] = attack_group["action"].title()

                    case "RFI":
                        if attack_group["action"] == "none":
                            policy["Remote File Inclusion"] = "Not Used"
                        else:
                            policy["Remote File Inclusion"] = attack_group["action"].title()

                    case "SQL":
                        if attack_group["action"] == "none":
                            policy["SQL Injection"] = "Not Used"
                        else:
                            policy["SQL Injection"] = attack_group["action"].title()

                    case "OUTBOUND":
                        if attack_group["action"] == "none":
                            policy["Total Outbound"] = "Not Used"
                        else:
                            policy["Total Outbound"] = attack_group["action"].title()

                    case "WAT":
                        if attack_group["action"] == "none":
                            policy["Web Attack Tool"] = "Not Used"
                        else:
                            policy["Web Attack Tool"] = attack_group["action"].title()

                    case "PLATFORM":
                        if attack_group["action"] == "none":
                            policy["Web Platform Attack"] = "Not Used"
                        else:
                            policy["Web Platform Attack"] = attack_group["action"].title()

                    case "POLICY":
                        if attack_group["action"] == "none":
                            policy["Web Policy Violation"] = "Not Used"
                        else:
                            policy["Web Policy Violation"] = attack_group["action"].title()

                    case "PROTOCOL":
                        if attack_group["action"] == "none":
                            policy["Web Protocol Attack"] = "Not Used"
                        else:
                            policy["Web Protocol Attack"] = attack_group["action"].title()

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]
    df1 = df1[
        [
            "Security Policy",
            "Security Configuration",
            "Web Application Firewall",
            "Management Mode",
            "Latest Update",
            "Command Injection",
            "Cross Site Scripting",
            "Local File Inclusion",
            "Remote File Inclusion",
            "SQL Injection",
            "Total Outbound",
            "Web Attack Tool",
            "Web Platform Attack",
            "Web Policy Violation",
            "Web Protocol Attack",
            "Penalty Box",
        ]
    ]

    return df1


def client_reputation(policy_settings, reputation_profiles):
    for policy in policy_settings:
        if "Reputation Profiles in Alert" in policy:
            for i in range(len(policy["Reputation Profiles in Alert"])):
                policy["Reputation Profiles in Alert"][i] = f"{reputation_profiles[policy['Reputation Profiles in Alert'][i]]} [{policy['Reputation Profiles in Alert'][i]}]"
            policy["Reputation Profiles in Alert"] = "\n".join(policy["Reputation Profiles in Alert"])
        else:
            policy["Reputation Profiles in Alert"] = float("NaN")

        if "Reputation Profiles in Deny" in policy:
            for i in range(len(policy["Reputation Profiles in Deny"])):
                policy["Reputation Profiles in Deny"][i] = f"{reputation_profiles[policy['Reputation Profiles in Deny'][i]]} [{policy['Reputation Profiles in Deny'][i]}]"
            policy["Reputation Profiles in Deny"] = "\n".join(policy["Reputation Profiles in Deny"])
        else:
            policy["Reputation Profiles in Deny"] = float("NaN")

        if "Not Used Reputation Profiles" in policy:
            for i in range(len(policy["Not Used Reputation Profiles"])):
                policy["Not Used Reputation Profiles"][i] = f"{reputation_profiles[policy['Not Used Reputation Profiles'][i]]} [{policy['Not Used Reputation Profiles'][i]}]"
            policy["Not Used Reputation Profiles"] = "\n".join(policy["Not Used Reputation Profiles"])
        else:
            policy["Not Used Reputation Profiles"] = float("NaN")

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]

    if (df1['Client Reputation'] == 'Off').all():
        df1 = pd.DataFrame()
    else:
        df1 = df1[
            [
                "Security Policy",
                "Security Configuration",
                "Client Reputation",
                "Reputation Profiles in Alert",
                "Reputation Profiles in Deny",
                "Not Used Reputation Profiles",
            ]
        ]

    return df1


def akamai_bots(policy_settings):
    for policy in policy_settings:
        if "akamaiBots" in policy:
            for bot_category in policy["akamaiBots"]:
                match bot_category["categoryId"]:
                    case "0c508e1d-73a4-4366-9e48-3c4a080f1c5d":
                        if bot_category["action"] == "none":
                            policy["Academic or Research Bots"] = "Skip"
                        else:
                            policy["Academic or Research Bots"] = bot_category["action"].title()

                    case "75493431-b41a-492c-8324-f12158783ce1":
                        if bot_category["action"] == "none":
                            policy["Automated Shopping Cart and Sniper Bots"] = "Skip"
                        else:
                            policy["Automated Shopping Cart and Sniper Bots"] = bot_category["action"].title()

                    case "8a70d29c-a491-4583-9768-7deea2f379c1":
                        if bot_category["action"] == "none":
                            policy["Business Intelligence Bots"] = "Skip"
                        else:
                            policy["Business Intelligence Bots"] = bot_category["action"].title()

                    case "47bcfb70-f3f5-458b-8f7c-1773b14bc6a4":
                        if bot_category["action"] == "none":
                            policy["E-Commerce Search Engine Bots"] = "Skip"
                        else:
                            policy["E-Commerce Search Engine Bots"] = bot_category["action"].title()

                    case "50395ad2-2673-41a4-b317-9b70742fd40f":
                        if bot_category["action"] == "none":
                            policy["Enterprise Data Aggregator Bots"] = "Skip"
                        else:
                            policy["Enterprise Data Aggregator Bots"] = bot_category["action"].title()

                    case "c6692e03-d3a8-49b0-9566-5003eeaddbc1":
                        if bot_category["action"] == "none":
                            policy["Financial Account Aggregator Bots"] = "Skip"
                        else:
                            policy["Financial Account Aggregator Bots"] = bot_category["action"].title()

                    case "53598904-21f5-46b1-8b51-1b991beef73b":
                        if bot_category["action"] == "none":
                            policy["Financial Services Bots"] = "Skip"
                        else:
                            policy["Financial Services Bots"] = bot_category["action"].title()

                    case "2f169206-f32c-48f7-b281-d534cf1ceeb3":
                        if bot_category["action"] == "none":
                            policy["Job Search Engine Bots"] = "Skip"
                        else:
                            policy["Job Search Engine Bots"] = bot_category["action"].title()

                    case "dff258d5-b1ad-4bbb-b1d1-cf8e700e5bba":
                        if bot_category["action"] == "none":
                            policy["Media or Entertainment Search Bots"] = "Skip"
                        else:
                            policy["Media or Entertainment Search Bots"] = bot_category["action"].title()

                    case "ade03247-6519-4591-8458-9b7347004b63":
                        if bot_category["action"] == "none":
                            policy["News Aggregator Bots"] = "Skip"
                        else:
                            policy["News Aggregator Bots"] = bot_category["action"].title()

                    case "36b27e0c-76fc-44a4-b913-c598c5af8bba":
                        if bot_category["action"] == "none":
                            policy["Online Advertising Bots"] = "Skip"
                        else:
                            policy["Online Advertising Bots"] = bot_category["action"].title()

                    case "b58c9929-9fd0-45f7-86f4-1d6259285c3c":
                        if bot_category["action"] == "none":
                            policy["RSS Feed Reader Bots"] = "Skip"
                        else:
                            policy["RSS Feed Reader Bots"] = bot_category["action"].title()

                    case "f7558c03-9033-46ce-bbda-10eeda62a5d4":
                        if bot_category["action"] == "none":
                            policy["SEO, Analytics or Marketing Bots"] = "Skip"
                        else:
                            policy["SEO, Analytics or Marketing Bots"] = bot_category["action"].title()

                    case "07782c03-8d21-4491-9078-b83514e6508f":
                        if bot_category["action"] == "none":
                            policy["Site Monitoring and Web Development Bots"] = "Skip"
                        else:
                            policy["Site Monitoring and Web Development Bots"] = bot_category["action"].title()

                    case "7035af8d-148c-429a-89da-de41e68c72d8":
                        if bot_category["action"] == "none":
                            policy["Social Media or Blog Bots"] = "Skip"
                        else:
                            policy["Social Media or Blog Bots"] = bot_category["action"].title()

                    case "831ef84a-c2bb-4b0d-b90d-bcd16793b830":
                        if bot_category["action"] == "none":
                            policy["Web Archiver Bots"] = "Skip"
                        else:
                            policy["Web Archiver Bots"] = bot_category["action"].title()

                    case "4e14219f-6568-4c9d-9bd8-b29ca2afc422":
                        if bot_category["action"] == "none":
                            policy["Web Search Engine Bots"] = "Skip"
                        else:
                            policy["Web Search Engine Bots"] = bot_category["action"].title()

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]
    
    if "Academic or Research Bots" in df1.columns:
        df1 = df1[
            [
                "Security Policy",
                "Security Configuration",
                "Bot Management",
                "Academic or Research Bots",
                "Automated Shopping Cart and Sniper Bots",
                "Business Intelligence Bots",
                "E-Commerce Search Engine Bots",
                "Enterprise Data Aggregator Bots",
                "Financial Account Aggregator Bots",
                "Financial Services Bots",
                "Job Search Engine Bots",
                "Media or Entertainment Search Bots",
                "News Aggregator Bots",
                "Online Advertising Bots",
                "RSS Feed Reader Bots",
                "SEO, Analytics or Marketing Bots",
                "Site Monitoring and Web Development Bots",
                "Social Media or Blog Bots",
                "Web Archiver Bots",
            ]
        ]
    else:
        
        df1 = pd.DataFrame()
    
    return df1


def bot_detections(policy_settings):
    for policy in policy_settings:
        if "botDetections" in policy:
            for bot_category in policy["botDetections"]:
                match bot_category["detectionId"]:
                    case "fda1ffb9-ef46-4570-929c-7449c0c750f8":
                        if bot_category["action"] == "none":
                            policy["Impersonators of Known Bots"] = "Skip"
                        else:
                            policy["Impersonators of Known Bots"] = bot_category["action"].title()

                    case "da005ad3-8bbb-43c8-a783-d97d1fb71ad2":
                        if bot_category["action"] == "none":
                            policy["Development Frameworks"] = "Skip"
                        else:
                            policy["Development Frameworks"] = bot_category["action"].title()

                    case "578dad32-024b-48b4-930c-db81831686f4":
                        if bot_category["action"] == "none":
                            policy["HTTP Libraries"] = "Skip"
                        else:
                            policy["HTTP Libraries"] = bot_category["action"].title()

                    case "872ed6c2-514c-4055-9c44-9782b1c783bf":
                        if bot_category["action"] == "none":
                            policy["Web Services Libraries"] = "Skip"
                        else:
                            policy["Web Services Libraries"] = bot_category["action"].title()

                    case "601192ae-f5e2-4a29-8f75-a0bcd3584c2b":
                        if bot_category["action"] == "none":
                            policy["Open Source Crawlers/Scraping Platforms"] = "Skip"
                        else:
                            policy["Open Source Crawlers/Scraping Platforms"] = bot_category["action"].title()

                    case "b88cba13-4d11-46fe-a7e0-b47e78892dc4":
                        if bot_category["action"] == "none":
                            policy["Headless Browsers/Automation Tools"] = "Skip"
                        else:
                            policy["Headless Browsers/Automation Tools"] = bot_category["action"].title()

                    case "074df68e-fb28-432a-ac6d-7cfb958425f1":
                        if bot_category["action"] == "none":
                            policy["Declared Bots (Keyword Match)"] = "Skip"
                        else:
                            policy["Declared Bots (Keyword Match)"] = bot_category["action"].title()

                    case "5bc041ad-c840-4202-9c2e-d7fc873dbeaf":
                        if bot_category["action"] == "none":
                            policy["Aggressive Web Crawlers"] = "Skip"
                        else:
                            policy["Aggressive Web Crawlers"] = bot_category["action"].title()

                    case "a3b92f75-fa5d-436e-b066-426fc2919968":
                        if bot_category["action"] == "none":
                            policy["Browser Impersonator"] = "Skip"
                        else:
                            policy["Browser Impersonator"] = bot_category["action"].title()

                    case "3f799d4b-33b9-496b-af87-9ad174779e3d":
                        if bot_category["action"] == "none":
                            policy["Request Anomaly (Deprecated)"] = "Skip"
                        else:
                            policy["Request Anomaly (Deprecated)"] = bot_category["action"].title()

                    case "9712ab32-83bb-43ab-a46d-4c2a5a42e7e2":
                        if bot_category["action"] == "none":
                            policy["Web Scraper Reputation"] = "Skip"
                        else:
                            policy["Web Scraper Reputation"] = bot_category["action"].title()

                    case "4f1fd3ea-7072-4cd0-8d12-24f275e6c75d":
                        if bot_category["action"] == "none":
                            policy["Cookie Integrity Failed"] = "Skip"
                        else:
                            policy["Cookie Integrity Failed"] = bot_category["action"].title()

                    case "1bb748e2-b3ad-41db-85fa-c69e62be59dc":
                        if bot_category["action"] == "none":
                            policy["Session Validation"] = "Skip"
                        else:
                            policy["Session Validation"] = bot_category["action"].title()

                    case "c5623efa-f326-41d1-9601-a2d201bedf63":
                        if bot_category["action"] == "none":
                            policy["Client Disabled JavaScript"] = "Skip"
                        else:
                            policy["Client Disabled JavaScript"] = bot_category["action"].title()

                    case "393cba3d-656f-48f1-abe4-8dd5028c6871":
                        if bot_category["action"] == "none":
                            policy["JavaScript Fingerprint Anomaly"] = "Skip"
                        else:
                            policy["JavaScript Fingerprint Anomaly"] = bot_category["action"].title()

                    case "c7f70f75-e3e2-4181-8ef8-30afb6576147":
                        if bot_category["action"] == "none":
                            policy["JavaScript Fingerprint Not Received"] = "Skip"
                        else:
                            policy["JavaScript Fingerprint Not Received"] = bot_category["action"].title()

    df1 = pd.DataFrame(policy_settings)
    df1["Security Policy"] = df1["policyName"] + " [" + df1["policyId"] + "]"
    df1["Security Configuration"] = df1["configName"]

    if "Impersonators of Known Bots" in df1.columns:

        if "Cookie Integrity Failed" in df1.columns:
            df1 = df1[
                [
                    "Security Policy",
                    "Security Configuration",
                    "Bot Management",
                    "Impersonators of Known Bots",
                    "Development Frameworks",
                    "HTTP Libraries",
                    "Web Services Libraries",
                    "Open Source Crawlers/Scraping Platforms",
                    "Headless Browsers/Automation Tools",
                    "Declared Bots (Keyword Match)",
                    "Aggressive Web Crawlers",
                    "Browser Impersonator",
                    "Request Anomaly (Deprecated)",
                    "Web Scraper Reputation",
                    "Cookie Integrity Failed",
                    "Session Validation",
                    "Client Disabled JavaScript",
                    "JavaScript Fingerprint Anomaly",
                    "JavaScript Fingerprint Not Received",
                ]
            ]
        else:
            df1 = df1[
                [
                    "Security Policy",
                    "Security Configuration",
                    "Bot Management",
                    "Impersonators of Known Bots",
                    "Development Frameworks",
                    "HTTP Libraries",
                    "Web Services Libraries",
                    "Open Source Crawlers/Scraping Platforms",
                    "Headless Browsers/Automation Tools",
                    "Declared Bots (Keyword Match)",
                    "Aggressive Web Crawlers",
                    "Browser Impersonator",
                    "Request Anomaly (Deprecated)",
                ]
            ]
    else:

        df1 = pd.DataFrame()

    return df1


def endpoint_protection(endpoint_coverage, api_search):
    api_endpoints_id = {}
    api_endpoints_basepath = {}
    for api in api_search["apiEndPoints"]:
        api_endpoints_id[api["apiEndPointId"]] = api["apiEndPointName"]
        api_endpoints_basepath[api["apiEndPointId"]] = api["basePath"]

    operations_id = {}
    operations_method = {}
    operations_resource = {}
    for operation in api_search["operations"]:
        operations_id[operation["operationId"]] = operation["operationName"]
        operations_method[operation["operationId"]] = operation["method"]
        operations_resource[operation["operationId"]] = operation["apiEndPointId"]

    # resources_path = {}
    # for resource in api_search["resources"]:
    #     resources_path[resource["apiResourceId"]] = resource["resourcePath"]

    endpoints = []

    for endpoint in endpoint_coverage:
        if endpoint["apiEndPointId"] in api_endpoints_id:
            endpoint["apiEndPointName"] = api_endpoints_id[endpoint["apiEndPointId"]]
        else:
            endpoint["apiEndPointName"] = endpoint["apiEndPointId"]

        if endpoint["operationId"] in operations_id:
            endpoint["operationName"] = operations_id[endpoint["operationId"]]
        else:
            endpoint["operationName"] = endpoint["operationId"]

        if "configName" in endpoint["configuration"]:
            endpoint["securityConfiguration"] = endpoint["configuration"]["configName"]
        else:
            endpoint["securityConfiguration"] = "WAF Security File"

        # endpoint["method"] = operations_method[endpoint["operationId"]]

        web_endpoint = {
            "API / Operation": f"{endpoint['apiEndPointName']} / {endpoint['operationName']}",
            "Security Configuration": endpoint["securityConfiguration"],
            "Security Policy": f"{endpoint['securityPolicy']['securityPolicyName']} [{endpoint['securityPolicy']['securityPolicyId']}]",
            "Telemetry Type": "Web Client - Standard",
        }

        if endpoint["telemetryTypeStates"]["standard"]["enabled"]:
            web_endpoint["Expected Traffic"] = "Enabled"
            if endpoint["traffic"]["standardTelemetry"]["aggressiveAction"] == "none":
                web_endpoint["Aggressive Response"] = "Skip"
            else:
                web_endpoint["Aggressive Response"] = endpoint["traffic"]["standardTelemetry"]["aggressiveAction"].title()

            if endpoint["traffic"]["standardTelemetry"]["strictAction"] == "none":
                web_endpoint["Strict Response"] = "Skip"
            else:
                web_endpoint["Strict Response"] = endpoint["traffic"]["standardTelemetry"]["strictAction"].title()
        else:
            web_endpoint["Expected Traffic"] = "Disabled"
            if endpoint["telemetryTypeStates"]["standard"]["disabledAction"] == "none":
                web_endpoint["Unexpected Requests"] = "Skip"
            else:
                web_endpoint["Unexpected Requests"] = endpoint["telemetryTypeStates"]["standard"]["disabledAction"].title()

        endpoints.append(web_endpoint)

        if endpoint["telemetryTypeStates"]["inline"]["enabled"]:
            inline_endpoint = {
                "API / Operation": f"{endpoint['apiEndPointName']} / {endpoint['operationName']}",
                "Security Configuration": endpoint["securityConfiguration"],
                "Security Policy": f"{endpoint['securityPolicy']['securityPolicyName']} [{endpoint['securityPolicy']['securityPolicyId']}]",
                "Telemetry Type": "Web Client - Inline",
                "Expected Traffic": "Enabled",
            }

            if endpoint["traffic"]["inlineTelemetry"]["aggressiveAction"] == "none":
                inline_endpoint["Aggressive Response"] = "Skip"
            else:
                inline_endpoint["Aggressive Response"] = endpoint["traffic"]["inlineTelemetry"]["aggressiveAction"].title()

            if endpoint["traffic"]["inlineTelemetry"]["strictAction"] == "none":
                inline_endpoint["Strict Response"] = "Skip"
            else:
                inline_endpoint["Strict Response"] = endpoint["traffic"]["inlineTelemetry"]["strictAction"].title()

            endpoints.append(inline_endpoint)

        if endpoint["telemetryTypeStates"]["nativeSdk"]["enabled"]:
            ios_endpoint = {
                "API / Operation": f"{endpoint['apiEndPointName']} / {endpoint['operationName']}",
                "Security Configuration": endpoint["securityConfiguration"],
                "Security Policy": f"{endpoint['securityPolicy']['securityPolicyName']} [{endpoint['securityPolicy']['securityPolicyId']}]",
                "Telemetry Type": "Native App - iOS SDK",
                "Expected Traffic": "Enabled",
            }

            if endpoint["traffic"]["nativeSdkIos"]["aggressiveAction"] == "none":
                ios_endpoint["Aggressive Response"] = "Skip"
            else:
                ios_endpoint["Aggressive Response"] = endpoint["traffic"]["nativeSdkIos"]["aggressiveAction"].title()

            if endpoint["traffic"]["nativeSdkIos"]["strictAction"] == "none":
                ios_endpoint["Strict Response"] = "Skip"
            else:
                ios_endpoint["Strict Response"] = endpoint["traffic"]["nativeSdkIos"]["strictAction"].title()

            endpoints.append(ios_endpoint)

            android_endpoint = {
                "API / Operation": f"{endpoint['apiEndPointName']} / {endpoint['operationName']}",
                "Security Configuration": endpoint["securityConfiguration"],
                "Security Policy": f"{endpoint['securityPolicy']['securityPolicyName']} [{endpoint['securityPolicy']['securityPolicyId']}]",
                "Telemetry Type": "Native App - Android",
                "Expected Traffic": "Enabled",
            }

            if endpoint["traffic"]["nativeSdkAndroid"]["aggressiveAction"] == "none":
                android_endpoint["Aggressive Response"] = "Skip"
            else:
                android_endpoint["Aggressive Response"] = endpoint["traffic"]["nativeSdkAndroid"]["aggressiveAction"].title()

            if endpoint["traffic"]["nativeSdkAndroid"]["strictAction"] == "none":
                android_endpoint["Strict Response"] = "Skip"
            else:
                android_endpoint["Strict Response"] = endpoint["traffic"]["nativeSdkAndroid"]["strictAction"].title()

            endpoints.append(android_endpoint)
        else:
            sdk_endpoint = {
                "API / Operation": f"{endpoint['apiEndPointName']} / {endpoint['operationName']}",
                "Security Configuration": endpoint["securityConfiguration"],
                "Security Policy": f"{endpoint['securityPolicy']['securityPolicyName']} [{endpoint['securityPolicy']['securityPolicyId']}]",
                "Telemetry Type": "Native App - SDK",
                "Expected Traffic": "Disabled",
            }

            if endpoint["telemetryTypeStates"]["nativeSdk"]["disabledAction"] == "none":
                sdk_endpoint["Unexpected Requests"] = "Skip"
            else:
                sdk_endpoint["Unexpected Requests"] = endpoint["telemetryTypeStates"]["nativeSdk"]["disabledAction"].title()

            endpoints.append(sdk_endpoint)

    df1 = pd.DataFrame(endpoints)

    if not df1.empty:
        df1 = df1[
            [
                "API / Operation",
                "Security Configuration",
                "Security Policy",
                "Telemetry Type",
                "Expected Traffic",
                "Aggressive Response",
                "Strict Response",
                "Unexpected Requests",
            ]
        ]

    return df1


def generate_hostname_waf_attackgroups(hostname_coverage: pd.DataFrame, waf_attackgroups: pd.DataFrame) -> pd.DataFrame:
    """
    Performs a cartesian product (cross join) between hostname_coverage and waf_attackgroups
    on matching 'SecurityPolicies' and 'SecurityPolicy' fields, returning the final DataFrame
    with the specified column order.
    """




    # Remove trailing pattern [(alphabets)_(numbers)] from 'Security Policy' column
    waf_attackgroups["Security Policy"] = waf_attackgroups["Security Policy"].str.replace(
        r'\[([a-zA-Z]+)_\d+\]$', '', regex=True)

    hostname_coverage.columns = hostname_coverage.columns.str.strip()
    waf_attackgroups.columns = waf_attackgroups.columns.str.strip()

    # Remove spaces from actual values in "Security Policy"
    waf_attackgroups["Security Policy"] = waf_attackgroups["Security Policy"].str.strip()

    # Also clean up hostname_coverage
    hostname_coverage["Security Policies"] = hostname_coverage["Security Policies"].str.strip()

    # Perform the cross join based on matching security policy fields
    hostname_waf_attackgroups = hostname_coverage.merge(
        waf_attackgroups,
        left_on="Security Policies",  # Column in hostname_coverage
        right_on="Security Policy",  # Column in waf_attackgroups
        how="inner",  # Keeps only matching records
        suffixes=("_host", "_waf")  # Prevents column name conflicts
    )

    # Define the required column order
    column_order = [
        "Hostname",
        "Security Configuration_host",
        "Security Policy",
        "Web Application Firewall",
        "Management Mode",
        "Latest Update",
        "Command Injection",
        "Cross Site Scripting",
        "Local File Inclusion",
        "Remote File Inclusion",
        "SQL Injection",
        "Total Outbound",
        "Web Attack Tool",
        "Web Platform Attack",
        "Web Policy Violation",
        "Web Protocol Attack",
        "Penalty Box",
    ]

    # Ensure the final DataFrame contains only the specified columns
    hostname_waf_attackgroups = hostname_waf_attackgroups[column_order]

    return hostname_waf_attackgroups

def getColumnOrder(mergeOperation: str):
    columnOrder = []
    if mergeOperation == "hostCoverageAndWAF":
        column_order = [
            "Hostname",
            "Security Configuration_host",
            "Security Policy",
            "Web Application Firewall",
            "Management Mode",
            "Latest Update",
            "Command Injection",
            "Cross Site Scripting",
            "Local File Inclusion",
            "Remote File Inclusion",
            "SQL Injection",
            "Total Outbound",
            "Web Attack Tool",
            "Web Platform Attack",
            "Web Policy Violation",
            "Web Protocol Attack",
            "Penalty Box",
        ]
    elif mergeOperation == "HostNameAndDos":
        column_order = [
            "Hostname",
            "Security Configuration_host",
            "Security Policy",
            "Rate Limiting Policies",
            "Rate Controls in Alert",
            "Rate Controls in Deny",
            "Not Used Rate Controls",
            "URL Protection Rules",
            "URL Protection Rules in Alert",
            "URL Protection Rules in Deny",
            "Not Used URL Protection Rules",
            "Slow POST Protection"
        ]

    return column_order

def generate_merged_dataframe(df1: pd.DataFrame, df2: pd.DataFrame, left_on: str, right_on: str, merge_type: str) -> pd.DataFrame:
    """
    Performs a cartesian product (cross join) between df1 and df2
    on matching fields provided as parameters, returning the final DataFrame
    with the specified column order.
    """

    # Remove trailing pattern [(alphabets)_(numbers)] from the right_on column in df2
    df2[right_on] = df2[right_on].str.replace(r'\[([a-zA-Z]+)_\d+\]$', '', regex=True)

    # Strip spaces from column names
    df1.columns = df1.columns.str.strip()
    df2.columns = df2.columns.str.strip()

    # Remove spaces from actual values in the join columns
    df1[left_on] = df1[left_on].str.strip()
    df2[right_on] = df2[right_on].str.strip()

    # Perform the cross join based on matching fields
    merged_df = df1.merge(
        df2,
        left_on=left_on,
        right_on=right_on,
        how="inner",
        suffixes=("_host", "_dos")  # Prevents column name conflicts
    )

    # Ensure the final DataFrame contains only the specified columns
    # Select first two columns from df1
    first_two_columns_df1 = ["Hostname"] + ["Security Configuration_host"] + ["Security Policy"]


    # Select all columns from df2 except the first one
    remaining_columns_df2 = list(df2.columns[2:])

    # Combine selected columns
    final_columns = first_two_columns_df1 + remaining_columns_df2


    merged_df = merged_df[final_columns]
    merged_df = merged_df.rename(columns={"Security Configuration_host": "Security Configuration"})

    return merged_df

