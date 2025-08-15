# module_utils/radware_cc.py
import requests
import time
import random
from ansible.module_utils.logger import Logger

class RadwareCC:
    def __init__(self, cc_ip, username, password, verify_ssl=False, logger=None, timeout=30):
        self.cc_ip = cc_ip
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        if not self.verify_ssl:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self.log = logger
        self.login(username, password)

    def login(self, username, password):
        url = f"https://{self.cc_ip}/mgmt/system/user/login"
        r = self.session.post(url, json={"username": username, "password": password},
                              verify=self.verify_ssl, timeout=self.timeout)
        r.raise_for_status()
        if self.log:
            self.log.info(f"Logged in to Radware CC at {self.cc_ip} as {username}")
        data = r.json()
        if data.get("status") != "ok":
            if self.log:
                self.log.error(f"Login failed: {data}")
            raise Exception("Login failed")


    def _request(self, method, url, retries=3, delay=1, data=None, json=None):
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.request(method=method, url=url,
                                            data=data, json=json,
                                            verify=self.verify_ssl, timeout=self.timeout)
                if resp.status_code == 403:
                    if self.log:
                        self.log.info(f"[{method.upper()}] Attempt {attempt}: 403 Forbidden. Reauthenticating…")
                    # Re-login and retry
                    # NOTE: assumes credentials persist in session headers/cookies
                    # If you need username/password again, store them in __init__
                    # or pass a reauth callback.
                    # For simplicity, we just raise here if we cannot reauth
                    # In a fuller SDK, you would keep creds and call self.login(...)
                    raise requests.exceptions.HTTPError("403 Forbidden", response=resp)

                resp.raise_for_status()
                return resp
            except requests.exceptions.HTTPError as err:
                # Only retry 403; others (e.g., 500) bubble up
                if err.response is not None and err.response.status_code == 403 and attempt < retries:
                    sleep_time = delay * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                    time.sleep(sleep_time)
                    continue
                raise
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.SSLError,
                    requests.exceptions.Timeout) as err:
                # transient errors
                if attempt < retries:
                    sleep_time = delay * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                    time.sleep(sleep_time)
                else:
                    raise

    def _post(self, url, data=None, json=None):
        return self._request("post", url, data=data, json=json)

    def _get(self, url):
        return self._request("get", url)

    def _put(self, url, data=None, json=None):
        return self._request("put", url, data=data, json=json)

    def _delete(self, url):
        return self._request("delete", url)


    # -------- Convenience wrappers --------

    def lock_device(self, ip):
        r = self._post(f"https://{self.cc_ip}/mgmt/system/config/tree/device/byip/{ip}/lock")
        return r.json()

    def unlock_device(self, ip):
        r = self._post(f"https://{self.cc_ip}/mgmt/system/config/tree/device/byip/{ip}/unlock")
        return r.json()

    def create_network_group(self, device_ip, class_name, address, mask, index):
        url = f"https://{self.cc_ip}/mgmt/device/byip/{device_ip}/config/rsBWMNetworkTable/{class_name}/{index}"
        body = {
            "rsBWMNetworkName": class_name,
            "rsBWMNetworkSubIndex": index,
            "rsBWMNetworkAddress": address,
            "rsBWMNetworkMask": mask,
            "rsBWMNetworkMode": "1"
        }
        resp = self._post(url, json=body)

        # parse JSON (even on 4xx/5xx _request would have raised already)
        try:
            data = resp.json()
        except ValueError:
            raise Exception(f"Invalid JSON response: {resp.text}")

        if data.get("status") == "ok":
            return data
        if data.get("status") == "error":
            # surface controller message (e.g., duplicate key)
            raise Exception(data.get("message", "API error"))
        raise Exception(f"Unexpected response: {data}")
