from urllib.parse import urljoin

from ratelimit import limits, sleep_and_retry


@sleep_and_retry
@limits(calls=100, period=60)
def search_operations(session, base_url):
    url = urljoin(base_url, "/api-definitions/v2/search-operations")
    query = {"queryType": "ACTIVE_IN_PRODUCTION", "includeDetails": "true"}

    response = session.get(url, params=query)

    return response
