from urllib.parse import urljoin

from ratelimit import limits, sleep_and_retry


@sleep_and_retry
@limits(calls=100, period=60)
def lists(session, base_url):
    url = urljoin(base_url, "/client-list/v1/lists")
    query = {"includeItems": "false", "includeDeprecated": "false", "sort": "type:ASC", "includeNetworkList": "true"}

    response = session.get(url, params=query)

    return response
