from urllib.parse import urljoin

from ratelimit import limits, sleep_and_retry


@sleep_and_retry
@limits(calls=100, period=60)
def account_switch_keys(session, base_url, account):
    url = urljoin(
        base_url, "/identity-management/v3/api-clients/self/account-switch-keys"
    )
    query = {"search": account}

    response = session.get(url, params=query)

    return response
