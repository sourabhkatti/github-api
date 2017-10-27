import requests
import sys
import json
import pprint


class controller:

    def get_user_info(self):
        endpoint = "https://api.github.com/user"
        header = {
            "Authorization": "token 6487b46fb3f6e4b2ad40811d46c28e3cd818d899",
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)

        print("Username is " + response["login"])

    def create_issue(self):
        endpoint = "https://api.github.com/repos/sourabhkatti/testeeg/issues"
        header = {
            "Authorization": "token 6487b46fb3f6e4b2ad40811d46c28e3cd818d899",
            "content-type": "application/json"
        }
        issue = {
            "title": "Found a bug #6",
            "body": "I'm having a problem with this."
        }

        r = requests.post(url=endpoint, headers=header, json=issue)
        response = json.loads(r.text)
        print(response)

    def list_issues(self):
        endpoint = "https://api.github.com/issues"
        header = {
            "Authorization": "token 6487b46fb3f6e4b2ad40811d46c28e3cd818d899",
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)
        print(response)


github_controller = controller()
# github_controller.getuserinfo()

github_controller.list_issues()
