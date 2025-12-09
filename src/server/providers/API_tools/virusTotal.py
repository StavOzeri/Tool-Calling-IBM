import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any
import logging

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="VitusTotal.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("VirusTotal MCP", json_response=True)

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = ""

# Helper function to make requests to VirusTotal API
async def make_get_request(url: str) -> dict[str, Any]:
    headers = {
        "x-apikey": API_KEY,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }


async def make_get_request_with_params(url : str, params : dict[str , Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }

    url += "?"
    for key, value in params.items():
        url += f"{key}={value}&"

    url = url[:-1]  
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }

async def make_post_request(url : str) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }
        
async def make_post_request_with_params(url : str, body : dict[str, Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, json = body,headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }

async def make_post_request_form(url: str, form: dict[str, Any]) -> dict[str, Any]:
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, json = form, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }

        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }

        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }


# tools    

#IP adresses
class InvalidIPAddressError(Exception):
    pass


@mcp.tool()
async def Get_an_IP_address_report(IP : str) -> dict[str, Any] | None :
    """
    Get an IP address report from VirusTotal.
    """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")

    logging.info("return: {data}")
    return data



@mcp.tool()
async def Request_an_IP_address_rescan(IP : str) -> dict[str, Any] | None :
    """
    Request an IP address rescan from VirusTotal.
    example: IP=' """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_an_IP_address(IP : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get comments on an IP address from VirusTotal.
    example: IP=' """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_to_an_IP_address(IP: str, comment: str) -> dict[str, Any] | None :
#     """
#     Add a comment to an IP address on VirusTotal.
#     example: IP=' ', comment='This is a test comment.'
#     """

#     if not is_valid_ip(IP):
#         raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

#     url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    
#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_IP_address(IP : str, relationship : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get objects related to an IP address from VirusTotal.
    example: IP=' '
    """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor


    url = f"{BASE_URL}/ip_addresses/{IP}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data

@mcp.tool()
async def Get_object_descriptors_related_to_an_IP_address(IP : str, relationship : str) -> dict[str, Any] | None :
    """
    Get object descriptors related to an IP address from VirusTotal.
    example: IP=' '
    """
    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/relationships/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_an_IP_address(IP : str) -> dict[str, Any] | None :
    """
    Get votes on an IP address from VirusTotal.
    example: IP=' '
    """
    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_to_an_IP_address(IP: str, vote: dict[str, Any]) -> dict[str, Any] | None :
#     """
#     Add a vote to an IP address on VirusTotal.
#     example: IP=' ', vote={'verdict': 'malicious'}
#     """
#     if not is_valid_ip(IP):
#         raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

#     url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    
#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#     	        "verdict": vote
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT IP report: {data['error']}")
#     logging.info("return: {data}")
#     return data



#Domains & Resolutions
class InvalidDomainError(Exception):
    pass

@mcp.tool()
async def Get_a_domain_report(domain: str) -> dict[str, Any] | None:
    """
    Get a domain report from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")

    url = f"{BASE_URL}/domains/{domain}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Request_an_domain_rescan(domain: str) -> dict[str, Any] | None:
    """
    Request a domain rescan from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/domains/{domain}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_a_domain(domain: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/domains/{domain}/comments"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_to_a_domain(domain: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a domain on VirusTotal.
#     example: domain='example.com', comment='This is a test comment.'
#     """
#     if not is_valid_domain(domain):
#         raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
#     url = f"{BASE_URL}/domains/{domain}/comments"
    
#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request(url, payload)

#     if data["error"]:
#         logging.error(f"Error in Domain report: {data['error']}")
#     logging.info("return: {data}")
#     return data


@mcp.tool()
async def Get_objects_related_to_a_domain(domain: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor
    
    url = f"{BASE_URL}/domains/{domain}/{relationship}"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_domain(domain: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/domains/{domain}/relationships/{relationship}"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_DNS_resolution_object(domain: str) -> dict[str, Any] | None:
    """
    Get a DNS resolution object from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/resolutions/{domain}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_a_domain(domain: str) -> dict[str, Any] | None:
    """
    Get votes on a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/domains/{domain}/votes"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_to_a_domain(domain: str, verdict : str) -> dict[str, Any] | None:
#     """
#     Add a vote to a domain on VirusTotal.
#     example: domain='example.com', verdict='malicious'
#     """
#     if not is_valid_domain(domain):
#         raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
#     url = f"{BASE_URL}/domains/{domain}/votes"
    
#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#                 "verdict": verdict
#             }
#         }
#     }

#     data = await make_post_request(url, payload)

#     if data["error"]:
#         logging.error(f"Error in Domain report: {data['error']}")
#     logging.info("return: {data}")
#     return data



#Files

@mcp.tool()
async def Upload_a_file(file_path: str, password: str | None = None) -> dict[str, Any] | None:
    """
    Upload and scan a file using VirusTotal.
    """
    url = f"{BASE_URL}/files"

    body = {
        "data": {
            "type": "file_upload",
            "attributes": {
                "file_path": file_path
            }
        }
    }

    if password:
        body["data"]["attributes"]["password"] = password

    data = await make_post_request_with_params(url, body)
    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_URL_for_uploading_large_files() -> dict[str, Any] | None:
    """
    Get a temporary upload URL for large files (>32MB).
    """
    url = f"{BASE_URL}/files/upload_url"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_file_report(file_id: str) -> dict[str, Any] | None:
    """
    Get a file report from VirusTotal.
    example: file_id='44d88612fea8a8f36de82e1278abb02f'
    """
    url = f"{BASE_URL}/files/{file_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data




@mcp.tool()
async def Request_a_file_rescan(file_id: str) -> dict[str, Any] | None:
    """
    Request a rescan (analysis) of a file on VirusTotal.
    """
    url = f"{BASE_URL}/files/{file_id}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_comments_on_a_file(file_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



# @mcp.tool()
# async def Add_a_comment_to_a_file(file_id: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a file.
#     """
#     url = f"{BASE_URL}/files/{file_id}/comments"

#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT File report: {data['error']}")
#     logging.info("return: {data}")
#     return data



@mcp.tool()
async def Get_objects_related_to_a_file(file_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_file(file_id: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to a file.
    """
    url = f"{BASE_URL}/files/{file_id}/relationships/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_crowdsourced_Sigma_rule_object(rule_id: str) -> dict[str, Any] | None:
    """
    Get a crowdsourced Sigma rule object.
    """
    url = f"{BASE_URL}/sigma_rules/{rule_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_crowdsourced_YARA_ruleset(ruleset_id: str) -> dict[str, Any] | None:
    """
    Get a crowdsourced YARA ruleset.
    """
    url = f"{BASE_URL}/yara_rulesets/{ruleset_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_votes_on_a_file(file_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get votes on a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/votes"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



# @mcp.tool()
# async def Add_a_vote_to_a_file(file_id: str, vote: str) -> dict[str, Any] | None:
#     """
#     Add a vote to a file.
#     example: vote='malicious' or 'harmless'
#     """
#     url = f"{BASE_URL}/files/{file_id}/votes"

#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#                 "verdict": vote
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT File report: {data['error']}")
#     logging.info("return: {data}")
#     return data


#File Behaviours
@mcp.tool()
async def Get_a_summary_of_all_behavior_reports_for_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get a summary of all behavior reports for a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviour_summary"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_summary_of_all_MITRE_ATTACK_techniques_observed_in_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get MITRE ATT&CK techniques summary observed in a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviour_mitre_trees"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_all_behavior_reports_for_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get all behaviour reports for a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviours"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_file_behaviour_report_from_a_sandbox(sandbox_id: str) -> dict[str, Any] | None:
    """
    Get a file behaviour report from a specific sandbox.
    """
    url = f"{BASE_URL}/file_behaviours/{sandbox_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_behaviour_report(sandbox_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a behaviour report.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_behaviour_report(sandbox_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a behaviour report.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_detailed_HTML_behaviour_report(sandbox_id: str) -> dict[str, Any] | None:
    """
    Get a detailed HTML behaviour report for a sandbox behaviour ID.
    """
    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/html"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



#URLs
class InvalidURLError(Exception):
    pass


@mcp.tool()
async def Scan_URL(url: str) -> dict[str, Any] | None:
    """
    Scan / analyze a URL using VirusTotal.
    """
    if not is_valid_url(url):
        raise InvalidURLError(f"The URL '{url}' is not valid.")

    endpoint = f"{BASE_URL}/urls"
    form_data = {"url": url}

    data = await make_post_request_form(endpoint, form_data)

    if data["error"]:
        logging.error(f"Error in VT URL scan: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_URL_report(url_id: str) -> dict[str, Any] | None:
    """
    Get a URL analysis report.
    Example url_id: a hash returned from Scan_URL
    """
    url = f"{BASE_URL}/urls/{url_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT URL report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Request_a_URL_rescan(url_id: str) -> dict[str, Any] | None:
    """
    Request a rescan (re-analysis) for a URL.
    """
    endpoint = f"{BASE_URL}/urls/{url_id}/analyse"
    data = await make_post_request(endpoint)

    if data["error"]:
        logging.error(f"Error in VT URL rescan: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_a_URL(url_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments for a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL comments: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_on_a_URL(url_id: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a URL.
#     """
#     url = f"{BASE_URL}/urls/{url_id}/comments"

#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error adding VT URL comment: {data['error']}")
#     logging.info("return: {data}")
#     return data



@mcp.tool()
async def Get_objects_related_to_a_URL(url_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching related VT URL objects: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_URL(url_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL relationship descriptors: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_a_URL(url_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get votes for a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/votes"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL votes: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_on_a_URL(url_id: str, verdict: str) -> dict[str, Any] | None:
#     """
#     Add a vote on a URL.
#     verdict must be either 'harmless' or 'malicious'.
#     """
#     url = f"{BASE_URL}/urls/{url_id}/votes"

#     payload = {
#         "type": "vote",
#         "attributes": {
#             "verdict": verdict
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error adding VT URL vote: {data['error']}")
#     logging.info("return: {data}")
#     return data


#comments

@mcp.tool()
async def Get_latest_comments(limit: int | None = 10, filter: str | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get information about the latest comments added to VirusTotal.
    """
    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/comments"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_comment_object(commentID: str, relationships: str | None = None) -> dict[str, Any] | None:
    """
    Get a comment object.
    """
    url = f"{BASE_URL}/comments/{commentID}"
    
    if relationships:
        params = {"relationships": relationships}
        data = await make_get_request_with_params(url, params)
    else:
        data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_comment(commentID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to a comment.
    """
    url = f"{BASE_URL}/comments/{commentID}/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_comment(commentID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a comment.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/comments/{commentID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Analyses, Submissions & Operations

@mcp.tool()
async def Get_a_URL_file_analysis(ID: str) -> dict[str, Any] | None:
    """
    Get a URL / file analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_analysis(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to an analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}/{relationship}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_analysis(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to an analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}/relationships/{relationship}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_submission_object(ID: str) -> dict[str, Any] | None:
    """
    Get a submission object.
    """
    url = f"{BASE_URL}/submission/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Submission report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_an_operation_object(ID: str) -> dict[str, Any] | None:
    """
    Get an operation object.
    """
    url = f"{BASE_URL}/operations/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Operation report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Attack Tactics

@mcp.tool()
async def Get_an_attack_tactic_object(ID: str) -> dict[str, Any] | None:
    """
    Get an attack tactic object.
    """
    url = f"{BASE_URL}/attack_tactics/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data 


@mcp.tool()
async def Get_objects_related_to_an_attack_tactic(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to an attack tactic.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_tactics/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_attack_tactic(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to an attack tactic.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_tactics/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Attack Techniques
@mcp.tool()
async def Get_an_attack_technique_object(ID: str) -> dict[str, Any] | None:
    """
    Get an attack technique object.
    """
    url = f"{BASE_URL}/attack_techniques/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_attack_technique(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to an attack technique.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_techniques/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_attack_technique(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to an attack technique.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_techniques/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Pupular Threat Categories

@mcp.tool()
async def Get_a_list_of_popular_threat_categories() -> dict[str, Any] | None:
    """
    Get a list of popular threat categories.
    """
    url = f"{BASE_URL}/popular_threat_categories"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Popular Threat Categories report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Code Insights

@mcp.tool()
async def Analyse_code_blocks_with_Code_Insights(code: str, code_type: str = "decompiled") -> dict[str, Any] | None:
    """
    Analyse code blocks with Code Insights.
    """
    url = f"{BASE_URL}/codeinsights/analyse-binary"
    
    # We need to import base64 at the top of the file
    code_b64 = base64.b64encode(code.encode('utf-8')).decode('utf-8')
    
    payload = {
        "data": {
            "code": code_b64,
            "code_type": code_type
        }
    }
    
    data = await make_post_request_with_params(url, payload)
    
    if data["error"]:
        logging.error(f"Error in VT Code Insights: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Search & Metadata
@mcp.tool()
async def Search_for_files_URLs_domains_IPs_and_comments(query: str) -> dict[str, Any] | None:
    """
    Search for files, URLs, domains, IPs and comments.
    """
    url = f"{BASE_URL}/search"
    params = {"query": query}
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Search: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_file_content_search_snippets(snippet: str) -> dict[str, Any] | None:
    """
    Get file content search snippets.
    """
    url = f"{BASE_URL}/intelligence/search/snippets/{snippet}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Intelligence Search Snippets: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_VirusTotal_metadata() -> dict[str, Any] | None:
    """
    Get VirusTotal metadata.
    """
    url = f"{BASE_URL}/metadata"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Metadata: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Collections

@mcp.tool()
async def Create_a_new_collection(data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Create a new collection.
    """
    url = f"{BASE_URL}/collections"
    
    # The API expects the body to be {"data": <collection object>}
    payload = {"data": data}
    
    data = await make_post_request_with_params(url, payload)
    if data["error"]:
        logging.error(f"Error in VT Create Collection: {data['error']}")
    logging.info(f"return: {data}")
    return data
 

 @mcp.tool()
async def Get_a_collection(ID: str) -> dict[str, Any] | None:
    """
    Get a collection.
    """
    url = f"{BASE_URL}/collections/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Collection report: {data['error']}")
    logging.info(f"return: {data}")
    return data

  
  @mcp.tool()
async def Get_comments_on_a_collection(ID: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/comments"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Comments: {data['error']}")
    logging.info(f"return: {data}")
    return data


 @mcp.tool()
async def Get_objects_related_to_a_collection(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_collection(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Object Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Zipping files

@mcp.tool()
async def Create_a_password_protected_ZIP_with_VirusTotal_files(hashes: list[str], password: str | None = None) -> dict[str, Any] | None:
    """
    Create a password-protected ZIP with VirusTotal files.
    """
    url = f"{BASE_URL}/intelligence/zip_files"
    
    data_content = {"hashes": hashes}
    if password:
        data_content["password"] = password
        
    payload = {"data": data_content}
    
    data = await make_post_request_with_params(url, payload)
    
    if data["error"]:
        logging.error(f"Error in VT Create ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_a_ZIP_file_s_status(ID: str) -> dict[str, Any] | None:
    """
    Check a ZIP file's status.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Status: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_ZIP_file_s_download_url(ID: str) -> dict[str, Any] | None:
    """
    Get a ZIP file's download URL.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}/download_url"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Download a ZIP file.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}/download"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Delete_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Delete a ZIP file.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}"
    data = await make_delete_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Delete: {data['error']}")
    logging.info(f"return: {data}")
    return data


#YARA Rules
@mcp.tool()
async def List_Crowdsourced_YARA_Rules(limit: int | None = 10, filter: str | None = None, order: str | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    List Crowdsourced YARA Rules.
    ACCEPTED FILTERS: author, creation_date, enabled, included_date, last_modification_date, name, tag, threat_category.
    ACCEPTED ORDERS: matches, creation_date, included_date, modification_date (append + or - for asc/desc).
    """
    url = f"{BASE_URL}/yara_rules"

    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    if order:
        params["order"] = order
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rules List: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_Crowdsourced_YARA_rule(ID: str) -> dict[str, Any] | None:
    """
    Get a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_Crowdsourced_YARA_rule(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}/{relationship}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_Crowdsourced_YARA_rule(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}/relationships/{relationship}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#IoC Stream

@mcp.tool()
async def Get_objects_from_the_IoC_Stream(limit: int | None = 10, descriptors_only: bool = False, filter: str | None = None, cursor: str | None = None, order: str | None = None) -> dict[str, Any] | None:
    """
    Get objects from the IoC Stream.
    The IoC stream endpoint returns different types of objects (files, URLs, domains, IP addresses).
    
    ALLOWED FILTERS:
    - date:2023-02-07T10:00:00+ (after)
    - date:2023-02-07- (before)
    - origin:hunting or origin:subscriptions
    - entity_id:objectId
    - entity_type:file (file, domain, url, ip_address)
    - source_type:hunting_ruleset (hunting_ruleset, retrohunt_job, collection, threat_actor)
    - source_id:objectId
    - notification_tag:ruleName
    
    ALLOWED ORDERS:
    - date- (default, most recent first)
    - date+ (oldest first)
    """
    url = f"{BASE_URL}/ioc_stream"
    
    params = {"limit": limit}
    if descriptors_only:
        params["descriptors_only"] = "true"
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    if order:
        params["order"] = order
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT IoC Stream: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_an_IoC_Stream_notification(ID: str) -> dict[str, Any] | None:
    """
    Get an IoC Stream notification.
    """
    url = f"{BASE_URL}/ioc_stream_notifications/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT IoC Stream Notification: {data['error']}")
    logging.info(f"return: {data}")
    return data


#VT Graph

@mcp.tool()
async def Search_graphs(limit: int | None = None, filter: str | None = None, cursor: str | None = None, order: str | None = None, attributes: str | None = None) -> dict[str, Any] | None:
    """
    Search graphs.
    
    SUPPORTED ORDER FIELDS: name, owner, creation_date, last_modification_date, views_count, comments_count.
    """
    url = f"{BASE_URL}/graphs"
    
    params = {}
    if limit:
        params["limit"] = limit
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    if order:
        params["order"] = order
    if attributes:
        params["attributes"] = attributes
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Search Graphs: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Create_a_graph(graph_content: dict[str, Any]) -> dict[str, Any] | None:
    """
    Create a graph.
    The graph_content should be the valid JSON structure for a VirusTotal graph.
    """
    url = f"{BASE_URL}/graphs"
    
    data = await make_post_request_with_params(url, graph_content)
    
    if data["error"]:
        logging.error(f"Error in VT Create Graph: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_graph_object(ID: str) -> dict[str, Any] | None:
    """
    Get a graph object.
    """
    url = f"{BASE_URL}/graphs/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Object: {data['error']}")
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_comments_on_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/comments"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Comments: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_graph(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_graph(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#VT Graph Permissions & ACL

@mcp.tool()
async def Get_users_and_groups_that_can_view_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get users and groups that can view a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/viewers"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Viewers: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_or_group_can_view_a_graph(ID: str, user_or_group_id: str) -> dict[str, Any] | None:
    """
    Check if a user or group can view a graph.
    """
    url = f"{BASE_URL}/graphs/{ID}/relationships/viewers/{user_or_group_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Graph Viewer: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_users_and_groups_that_can_edit_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get users and groups that can edit a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/editors"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Editors: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_or_group_can_edit_a_graph(ID: str, user_or_group_id: str) -> dict[str, Any] | None:
    """
    Check if a user or group can edit a graph.
    """
    url = f"{BASE_URL}/graphs/{ID}/relationships/editors/{user_or_group_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Graph Editor: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Zipping private files	
# 							
@mcp.tool()
async def Create_a_password_protected_ZIP_with_VirusTotal_private_files(hashes: list[str], password: str | None = None) -> dict[str, Any] | None:
    """
    Create a password-protected ZIP with VirusTotal private files.
    """
    url = f"{BASE_URL}/private/zip_files"
    
    body = {
        "data": {
            "hashes": hashes
        }
    }
    if password:
        body["data"]["password"] = password
        
    data = await make_post_request_with_params(url, body)
    
    if data["error"]:
        logging.error(f"Error in VT Create Private ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_a_ZIP_file_s_status(ID: str) -> dict[str, Any] | None:
    """
    Check a ZIP file's status.
    The status attribute contains one of: starting, creating, finished, timeout, error-starting, error-creating.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Status: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_ZIP_file_s_download_url(ID: str) -> dict[str, Any] | None:
    """
    Get a ZIP file's download URL.
    Returns a signed URL. The URL expires after 1 hour.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}/download_url"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Download a ZIP file.
    This endpoint redirects to the download URL.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}/download"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Download ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


#User Management

@mcp.tool()
async def Get_a_user_object(ID: str) -> dict[str, Any] | None:
    """
    Get a user object.
    ID can be User ID or API key.
    """
    url = f"{BASE_URL}/users/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Get User: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_user(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a user.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/users/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT User Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_user(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a user.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/users/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT User Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Graph Management

@mcp.tool()
async def Get_a_group_object(ID: str) -> dict[str, Any] | None:
    """
    Get a group object.
    """
    url = f"{BASE_URL}/groups/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Get Group: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_administrators_for_a_group(ID: str) -> dict[str, Any] | None:
    """
    Get administrators for a group.
    """
    url = f"{BASE_URL}/groups/{ID}/relationships/administrators"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Group Administrators: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_is_a_group_admin(group_id: str, user_id: str) -> dict[str, Any] | None:
    """
    Check if a user is a group admin.
    """
    url = f"{BASE_URL}/groups/{group_id}/relationships/administrators/{user_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Group Admin: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_group_users(ID: str) -> dict[str, Any] | None:
    """
    Get group users.
    """
    url = f"{BASE_URL}/groups/{ID}/relationships/users"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Group Users: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_is_a_group_member(group_id: str, user_id: str) -> dict[str, Any] | None:
    """
    Check if a user is a group member.
    """
    url = f"{BASE_URL}/groups/{group_id}/relationships/users/{user_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Group Member: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_group(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a group.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/groups/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Group Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_group(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a group.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/groups/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Group Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data



def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()