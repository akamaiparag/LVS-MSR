from urllib.parse import urljoin

from ratelimit import limits, sleep_and_retry


@sleep_and_retry
@limits(calls=100, period=60)
def configs(session, base_url):
    url = urljoin(base_url, "/appsec/v1/configs")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def hostname_coverage(session, base_url):
    url = urljoin(base_url, "/appsec/v1/hostname-coverage")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def configuration_details(configuration):
    configuration_details = {"configId": configuration["id"], "configName": configuration["name"], "versionNumber": configuration["productionVersion"]}

    return configuration_details


@sleep_and_retry
@limits(calls=100, period=60)
def security_policies(session, base_url, configId, versionNumber):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def rate_policies(session, base_url, configId, versionNumber):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/rate-policies")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def url_protections(session, base_url, configId, versionNumber):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/url-protections")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def reputation_profiles(session, base_url, configId, versionNumber):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/reputation-profiles")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def evasive_path_match(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/advanced-settings/evasive-path-match")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def request_body(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/advanced-settings/request-body")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def logging(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/advanced-settings/logging")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def attack_payload(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/advanced-settings/logging/attack-payload")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def pragma_header(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/advanced-settings/pragma-header")
    response = session.get(url)

    if response.status_code == 200:
        if response.json()["override"]:
            return response

        else:
            url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/advanced-settings/pragma-header")
            response = session.get(url)
            return response

    else:
        return response


@sleep_and_retry
@limits(calls=100, period=60)
def security_controls(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def ipgeo_firewall(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/ip-geo-firewall")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def rate_policies_action(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/rate-policies")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def url_protections_action(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/url-protections")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def slow_post(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/slow-post")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def waf_mode(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/mode")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def attack_groups(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/attack-groups")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def penalty_box(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/penalty-box")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def reputation_profiles_action(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/reputation-profiles")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def akamai_bot_actions(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/akamai-bot-category-actions")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def bot_detection_actions(session, base_url, configId, versionNumber, policyId):
    url = urljoin(base_url, f"/appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/bot-detection-actions")
    response = session.get(url)

    return response


@sleep_and_retry
@limits(calls=100, period=60)
def endpoint_coverage(session, base_url):
    url = urljoin(base_url, "/appsec/v1/bot-endpoint-coverage-report")
    response = session.get(url)

    return response
