import requests
import sys
import json
import pprint
import base64


class controller:
    personal_access_token = "3fc6abbd0c73ebd54a8694d4bda66bc9071bb38d"
    assignee = ""

    def get_user_info(self):
        endpoint = "https://api.github.com/user"
        header = {
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)

        print("Username is " + response["login"])

    def create_issue(self):
        endpoint = "https://api.github.com/repos/sourabhkatti/github-api/issues"
        header = {
            "Authorization": "token %s" % self.personal_access_token,
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
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)
        print(response)

    def get_assignees(self):
        endpoint = "https://api.github.com/repos/sourabhkatti/github-api/assignees"
        header = {
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }
        r = requests.get(url=endpoint, headers=header)
        request = json.loads(r.text)

        assignee_input = 0
        for i, user in enumerate(request):
            print(str(i + 1) + ". " + user["login"])
        assignee_input = int(input(
            "\nWhich user would you like to assign to these issues?\nInput 0 if you don't want to set an assignee.\n"))
        while assignee_input < 0 or assignee_input > request.__len__():
            print("Please choose a valid number.")
            assignee_input = int(input(
                "\nWhich user would you like to assign to these issues?\nInput 0 if you don't want to set an assignee.\n"))
        self.assignee = request[assignee_input - 1]["login"]
        print(self.assignee + " set as the assignee!")

    def get_teamserver_info(self):
        switch = 0
        if switch is not 0:
            print("Please provide the following details about your Contrast Teamserver account.")
            username = input("What is your username? ")
            api_key = input("What is your API Key? ")
            service_key = input("What is your Service Key? ")
            tag_name = input("Which tag should be used to open Github issues for? ")
        else:
            username = "sourabh.katti@contrastsecurity.com"
            api_key = "67yNesJ9R3dFf64fUrG3eeR6bM2Qn7Kn"
            service_key = "PJF4OWSSX6BZF9D3"
            tag_name = "sourabh"

        tagged_vulns = self.get_vulns_by_tag(username, api_key, service_key, tag_name)

    def get_vulns_by_tag(self, username, api_key, service_key, tag_name):
        endpoint = "https://app.contrastsecurity.com/Contrast/api/ng/e264d365-25e4-409e-a129-ec4c684c9d50/orgtraces" \
                   "/ids?expand=application,servers,violations,bugtracker," \
                   "skip_links&filterTags=%s&quickFilter=OPEN&sort=-lastTimeSeen" % tag_name

        AUTHORIZATION = base64.b64encode((username + ':' + service_key).encode('utf-8'))

        header = {
            "Authorization": AUTHORIZATION,
            "API-Key": api_key
        }

        # Get vulnerabilities for a tag
        r = requests.get(url=endpoint, headers=header)
        tagged_vulns = {}
        if json.loads(r.text)['traces'].__len__() > 0:
            for vuln in json.loads(r.text)['traces']:
                trace_url = "https://app.contrastsecurity.com/Contrast/static/ng/index.html#/e264d365-25e4-409e-a129-ec4c684c9d50/vulns/%s/overview" % vuln
                tagged_vulns[vuln] = {"trace_uuid": vuln, "url": trace_url}
            print(("\nFound %d vulnerabilities which have been tagged as '%s'") % (tagged_vulns.__len__(), tag_name))
            print(tagged_vulns)
        else:
            print("No vulnerabilities found for tag '%s'" % tag_name)

        self.get_vuln_details(header, tagged_vulns)

    def get_vuln_details(self, header, traces):

        for trace, trace_obj in traces.items():
            endpoint = "https://app.contrastsecurity.com/Contrast/api/ng/e264d365-25e4-409e-a129-ec4c684c9d50/traces/%s/story" % trace
            r = requests.get(url=endpoint, headers=header)
            response = json.loads(r.text)

            print(response)
            # print(trace_obj)


github_controller = controller()

# github_controller.getuserinfo()

# github_controller.create_issue()

# github_controller.list_issues()

# github_controller.get_assignees()

github_controller.get_teamserver_info()
