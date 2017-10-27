import requests
import sys
import json
import pprint


class controller:

    def get_user_info(self):
        endpoint = "https://api.github.com/user"
        header = {
            "Authorization": "token 7f5a5cbb61a6319e5708bedcd6f038b384e85c57",
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)

        print("Username is " + response["login"])

    def create_issue(self):
        endpoint = "https://api.github.com/repos/sourabhkatti/testeeg/issues"
        header = {
            "Authorization": "token 7f5a5cbb61a6319e5708bedcd6f038b384e85c57",
            "content-type": "application/json"
        }
        issue = {
            "title": "Found a bug",
            "body": "I'm having a problem with this."
        }

        r = requests.post(url=endpoint, headers=header, json=issue)
        response = json.loads(r.text)
        print(response)


github_controller = controller()
# github_controller.getuserinfo()

github_controller.create_issue()
