import requests
import json
import pprint
import base64
import re
import os
import argparse


class controller:

    assignee = ""

    TEAMSERVER_BASE_URL = ""
    ORGANIZATION_UUID = ""
    API_KEY = ""
    SERVICE_KEY = ""
    TEAMSERVER_USERNAME = ""
    TEAMSERVER_VULN_TAG = ""

    GITHUB_USERNAME = ""
    GITHUB_REPO_NAME = ""

    def __init__(self):
        parser = argparse.ArgumentParser(description='Choose whether to point to Github Enterprise or Gitlab')

        parser.add_argument("--url", help='Specify the Github URL to point to', nargs=1,
                            type=str, metavar="")

        argt = parser.parse_args()
        if argt.url:
            self.GITHUB_URL = argt.url[0]
            if self.GITHUB_URL[-1] is not '/':
                self.TEAMSERVER_BASE_URL += '/'
        else:
            self.GITHUB_URL = "https://api.github.com/"




    def create_issue(self, title, description):
        endpoint = self.GITHUB_URL + "repos/%s/%s/issues" % (self.GITHUB_USERNAME, self.GITHUB_REPO_NAME)
        header = {
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }
        issue = {
            "title": title,
            "body": description
        }

        r = requests.post(url=endpoint, headers=header, json=issue)
        response = json.loads(r.text)
        # print(response)
        return response['html_url']

    def list_issues(self):
        endpoint = self.GITHUB_URL + "issues"
        header = {
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }

        r = requests.get(url=endpoint, headers=header)
        response = json.loads(r.text)
        print(response)

    def get_assignees(self):
        endpoint = self.GITHUB_URL + "repos/%s/%s/assignees" % (self.GITHUB_USERNAME, self.GITHUB_REPO_NAME)
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

        # Get the teamserver URL
        try:
            self.TEAMSERVER_BASE_URL = os.environ['CONTRAST_TEAMSERVER_URL']
            if self.TEAMSERVER_BASE_URL[-1] is not '/':
                self.TEAMSERVER_BASE_URL += '/'
        except:
            print("Please set the CONTRAST_TEAMSERVER_URL environment variable to point to your teamserver location. The teamserver URL should end in /Contrast/api/ng/. For example, "
                  "CONTRAST_TEAMSERVER_URL=https://app.contrastsecurity.com/Contrast/api/ng/")
            return

        # Get teamserver organization ID
        try:
            self.ORGANIZATION_UUID = os.environ['CONTRAST_ORGANIZATION_ID']
            if self.ORGANIZATION_UUID[-1] is not '/':
                self.ORGANIZATION_UUID += '/'
        except:
            print("Please set the CONTRAST_ORGANIZATION_ID environment variable to your organization's ID.")
            return

        # Get teamserver username
        try:
            self.TEAMSERVER_USERNAME = os.environ['CONTRAST_USERNAME']
        except:
            print("Please set the CONTRAST_USERNAME environment variable to the username you use to log in to the teamserver.")
            return

        # Get API Key
        try:
            self.API_KEY = os.environ['CONTRAST_API_KEY']
        except:
            print("Please set the CONTRAST_API_KEY environment variable to your Contrast API Key. Please check here for "
                  "steps on how to get your API Key: https://docs.contrastsecurity.com/tools-apiaccess.html")
            return

        # Get Service Key
        try:
            self.SERVICE_KEY = os.environ['CONTRAST_SERVICE_KEY']
        except:
            print("Please set the CONTRAST_SERVICE_KEY environment variable to your Service Key. Please check here for "
                  "steps on how to get your Service Key: https://docs.contrastsecurity.com/tools-apiaccess.html")
            return

        # Get Teamserver vuln tag
        try:
            self.TEAMSERVER_VULN_TAG = os.environ['CONTRAST_TEAMSERVER_TAG']
        except:
            print("Please set the CONTRAST_TEAMSERVER_TAG environment variable to the tag which you designated to vulnerabilities you want to open a"
                  "Github issue for.")
            return


        try:
            self.GITHUB_USERNAME = os.environ['GITHUB_USERNAME']
        except:
            print("Please set the GITHUB_USERNAME environment variable to the username you use to log in to Github.")
            return

        # Get Teamserver repository name
        try:
            self.GITHUB_REPO_NAME = os.environ['GITHUB_REPO_NAME']
        except:
            print("Please set the GITHUB_REPO_NAME environment variable to the name of your repository in Github.")
            return

        # Get Github personal access token
        try:
            self.personal_access_token = os.environ['GITHUB_ACCESS_TOKEN']
        except:
            print("Please set the GITHUB_ACCESS_TOKEN environment variable to your Github Personal Access Token. If you're not sure what that is, please check out https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/")
            return

        # Check whether Github credentials are correct
        github_check = self.get_user_info()
        if github_check is 0:
            tagged_vulns = self.get_vulns_by_tag()
            if tagged_vulns == -1:
                print("\nUnable to connect to teamserver. Please check the API and Service key, username and teamserver URL.")
            elif tagged_vulns == 0:
                return
            else:
                # print(tagged_vulns.keys().__len__())
                issue_num = 1
                print("\nCreating issues in Github for parsed vulnerabilities")
                for issue in tagged_vulns.values():
                    issue_url = self.create_issue(issue["title"], issue["description"])
                    self.update_vulns_with_github_details(issue["trace_uuid"], issue_url)
                    url_string = ". Issue created: %s " % issue_url
                    print(str(issue_num) + url_string)
                    issue_num += 1
        else:
            print("\nUnable to connect to your Github account. Check your Github username and Authorization hash.")


    def get_user_info(self):
        endpoint = self.GITHUB_URL + "user"
        header = {
            "Authorization": "token %s" % self.personal_access_token,
            "content-type": "application/json"
        }

        try:
            r = requests.get(url=endpoint, headers=header)
            response = json.loads(r.text)
            try:
                if response['message'] == "Bad credentials":
                    print("ERROR: " + response['message'] + ". Please check your Github username and Authorization header (%s)" % response['documentation_url'])
                    return -1
                else:
                    # print("Username is " + response["login"])
                    return 0
            except:
                return 0
        except Exception as e:
            print("ERROR: " + str(e))
            return -1

    def get_vulns_by_tag(self):
        # Endpoint for tag to open vulnerabilities for (self.TEAMSERVER_VULN_TAG)
        endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "orgtraces" \
                                                                       "/ids?expand=application,servers,violations,bugtracker," \
                                                                       "skip_links&filterTags=%s&quickFilter=OPEN&sort=-lastTimeSeen" % self.TEAMSERVER_VULN_TAG

        # Endpoint for tah which already have an issue opened for them (tag = github-issue-created)
        verify_endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "orgtraces" \
                                                                              "/ids?expand=application,servers,violations,bugtracker," \
                                                                              "skip_links&filterTags=%s&quickFilter=OPEN&sort=-lastTimeSeen" % "github-issue-created"

        AUTHORIZATION = base64.b64encode((self.TEAMSERVER_USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))

        header = {
            "Authorization": AUTHORIZATION,
            "API-Key": self.API_KEY
        }

        # Get vulnerabilities for a tag
        try:
            # Get all vulns which need an issue opemed for them
            r = requests.get(url=endpoint, headers=header)

            # Get all vulns which have Github issues opened for them
            r_verify = requests.get(url=verify_endpoint, headers=header)
        except Exception as e:
            print("ERROR: Unable to connect to teamserver. Please check your authentication details.")
            print(e)
            return -1

        tagged_vulns = {}
        verify_vulns = json.loads(r_verify.text)
        try:
            if json.loads(r.text)['traces'].__len__() > 0:
                for vuln in json.loads(r.text)['traces']:
                    if vuln not in verify_vulns['traces']:  # Only open Github issues for vulns which are not tagged with "github-issue-created"
                        trace_url = self.TEAMSERVER_BASE_URL + "index.html#/" + self.ORGANIZATION_UUID + "vulns/%s/overview" % vuln
                        trace_url = trace_url.replace("api", "static")
                        tagged_vulns[vuln] = {"trace_uuid": vuln, "url": trace_url}
                print("\nFound %d vulnerabilities which have been tagged as '%s' and not with 'github-issue-created'" % (
                    tagged_vulns.__len__(), self.TEAMSERVER_VULN_TAG))
                # print(tagged_vulns)
            else:
                print("No vulnerabilities found for tag '%s'" % self.TEAMSERVER_VULN_TAG)

            if tagged_vulns.__len__() == 0:
                return 0
            else:
                return self.get_vuln_details(header, tagged_vulns)
        except Exception as e:
            print("\nERROR: " + verify_vulns['messages'][0])


    def get_vuln_details(self, header, traces):
        issues_to_send = {}
        issue_num = 1
        for trace, trace_obj in traces.items():
            print((str(issue_num) + ". Parsing %s" % trace_obj['trace_uuid'] + " .......... "), end="")

            # Set title for the Github issue
            endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "/traces/%s/card" % trace
            r = requests.get(url=endpoint, headers=header)
            trace_card = json.loads(r.text)
            issue_title = trace_card['card']['title']
            trace_obj["issue_title"] = issue_title

            # Set body of the Github issue
            endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "/traces/%s/story" % trace
            r = requests.get(url=endpoint, headers=header)
            trace_story = json.loads(r.text)
            trace_chapters = trace_story['story']['chapters']
            trace_risk = trace_story['story']['risk']

            # Get Recommendation for each trace
            endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "traces/%s/recommendation" % trace
            r = requests.get(url=endpoint, headers=header)
            trace_recommendation = json.loads(r.text)

            # Parse out issue body (story and risk)

            issue_body = self.parse_issue_body(trace_chapters, trace_risk, trace_obj['url'], trace_obj['trace_uuid'],
                                               trace_recommendation["recommendation"])
            # print(issue_body)

            issues_to_send[issue_num] = {"title": issue_title, "description": issue_body,
                                         "trace_uuid": trace_obj['trace_uuid']}
            issue_num += 1
            # sys.stdout.flush()
            print("Done!")

        return issues_to_send

    def parse_issue_body(self, chapters, raw_risk, trace_url, trace_uuid, raw_recommendation):
        # print(chapters.__len__())
        # print(trace_url, trace_uuid)

        issue_body = "**Trace UUID**: " + trace_uuid + "\n\n" + trace_url + "\n### Description\n"
        markdown_tag_matcher = re.compile('\{+[\/\w\#]+\}+')
        # markdown_tag_matcher = re.compile(r'{')

        for chapter in chapters:

            # print(chapter['introText'])
            if chapter['type'] == 'configuration':
                introText = chapter['introText']
                issue_body += ("\n\n" + chapter['introText'])
                matches = re.findall(markdown_tag_matcher, issue_body)
                if matches:
                    # print(matches)
                    for match in matches:
                        if match.__contains__('code'):
                            issue_body = issue_body.replace(match, "`")
                        elif match.__contains__('link'):
                            issue_body = issue_body.replace(match, "")
                            # print(issue_body)
                intro_body = chapter["body"]
                issue_body += "\n```\n" + intro_body + "\n```"

            elif chapter['type'] == 'source':
                issue_body += ("\n\n" + chapter['introText'])
                matches = re.findall(markdown_tag_matcher, issue_body)
                # print(issue_body)
                if matches:
                    # print(matches)
                    for match in matches:
                        if match.__contains__('code'):
                            issue_body = issue_body.replace(match, "`")
                        elif match.__contains__('link'):
                            issue_body = issue_body.replace(match, "")
                intro_body = chapter["body"]
                issue_body += "\n```\n" + intro_body + "\n```"
                # print(issue_body)

            elif chapter['type'] == 'properties':
                issue_body += ("\n\n" + chapter['introText'])
                matches = re.findall(markdown_tag_matcher, issue_body)
                # print(issue_body)
                if matches:
                    # print(matches)
                    for match in matches:
                        if match.__contains__('code'):
                            issue_body = issue_body.replace(match, "`")
                        elif match.__contains__('link'):
                            issue_body = issue_body.replace(match, "")
                            # print(issue_body)
                pages = chapter["properties"].keys()
                for page in pages:
                    issue_body += "\n```\n" + page + "\n```"

            elif chapter['type'] == 'location':
                issue_body += ("\n\n" + chapter['introText'])
                matches = re.findall(markdown_tag_matcher, issue_body)
                # print(issue_body)
                if matches:
                    # print(matches)
                    for match in matches:
                        if match.__contains__('code'):
                            issue_body = issue_body.replace(match, "`")
                        elif match.__contains__('link'):
                            issue_body = issue_body.replace(match, "")
                            # print(issue_body)
                intro_body = chapter["body"]
                issue_body += "\n```\n" + intro_body + "\n```"

            elif chapter['type'] == 'dataflow':
                issue_body += ("\n\n" + chapter['introText'])
                matches = re.findall(markdown_tag_matcher, issue_body)
                # print(issue_body)
                if matches:
                    # print(matches)
                    for match in matches:
                        if match.__contains__('code'):
                            issue_body = issue_body.replace(match, "`")
                        elif match.__contains__('link'):
                            issue_body = issue_body.replace(match, "")
                            # print(issue_body)
                intro_body = chapter["body"]
                issue_body += "\n```\n" + intro_body + "\n```"

        # Setup Risk comments
        risk = self.parse_risk(raw_risk)
        issue_body += "\n### Risk\n" + risk

        # Setup Recommendation
        recommendation = self.parse_recommendation(raw_recommendation)
        issue_body += "\n### Recommendation to fix this finding\n" + recommendation

        # print(issue_body)
        return issue_body

    def parse_risk(self, risk):
        raw_risk = risk["formattedText"]
        markdown_tag_matcher = re.compile('\{+[\/\w\#]+\}+')
        new_line_matcher = re.compile('[\\n]{4}[\s]+')  # Insert a new line if match if found
        bold_new_line_matcher = re.compile('\\n\\t\\n')  # Insert a new line and bold if match is found
        markdown_matches = re.findall(markdown_tag_matcher, raw_risk)
        if markdown_matches:
            # print(matches)
            for match in markdown_matches:
                if match.__contains__("focus"):
                    raw_risk = raw_risk.replace(match, "`")
                else:
                    raw_risk = raw_risk.replace(match, "")
        new_line_matches = re.findall(new_line_matcher, raw_risk)
        if new_line_matches:
            for match in new_line_matches:
                raw_risk = raw_risk.replace(match, ' ')
        bold_new_line_matches = re.findall(bold_new_line_matcher, raw_risk)
        if bold_new_line_matches:
            for match in bold_new_line_matches:
                raw_risk = raw_risk.replace(match, '\n### ')
        return raw_risk

    def parse_recommendation(self, recommendation):
        raw_recommendation = recommendation["formattedText"]
        markdown_tag_matcher = re.compile('\{+[\/\w\#]+\}+')
        new_line_matcher = re.compile('[\\n]{4}[\s]+')  # Insert a new line if match if found
        bold_new_line_matcher = re.compile('\\n\\t\\n')  # Insert a new line and bold if match is found

        markdown_matches = re.findall(markdown_tag_matcher, raw_recommendation)
        if markdown_matches:
            # print(matches)
            for match in markdown_matches:
                if match.__contains__("javaBlock"):
                    raw_recommendation = raw_recommendation.replace(match, "\n```\n")
                elif match.__contains__("code"):
                    raw_recommendation = raw_recommendation.replace(match, "`")
                elif match.__contains__("focus"):
                    raw_recommendation = raw_recommendation.replace(match, "**")
                elif match.__contains__("listElement"):
                    listmatcher = re.compile('[\ ]+\{+[\/\w\#]+\}+')
                    listmatches = re.findall(listmatcher, raw_recommendation)
                    for listmatch in listmatches:
                        raw_recommendation = raw_recommendation.replace(listmatch, "- ")
                elif match.__contains__("link"):
                    linkmatcher = re.compile("\n?\{+[\/link\#]+\}+")
                    linkmatches = re.findall(linkmatcher, raw_recommendation)
                    for linkmatch in linkmatches:
                        raw_recommendation = raw_recommendation.replace(linkmatch, " ")
                else:
                    raw_recommendation = raw_recommendation.replace(match, "")
                raw_recommendation = raw_recommendation.replace(match, "`")

        new_line_matches = re.findall(new_line_matcher, raw_recommendation)
        if new_line_matches:
            for match in new_line_matches:
                raw_recommendation = raw_recommendation.replace(match, ' ')

        bold_new_line_matches = re.findall(bold_new_line_matcher, raw_recommendation)
        if bold_new_line_matches:
            for match in bold_new_line_matches:
                raw_recommendation = raw_recommendation.replace(match, '\n#### ')
        return raw_recommendation

    def update_vulns_with_github_details(self, trace_uuid, issue_url):
        endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "orgtraces/filter/tags/listing?expand" \
                                                                       "=skip_links&filterText=%s&quickFilter=OPEN" % str(
            trace_uuid)
        AUTHORIZATION = base64.b64encode((self.TEAMSERVER_USERNAME + ':' + self.SERVICE_KEY).encode('utf-8'))
        header = {
            "Authorization": AUTHORIZATION,
            "API-Key": self.API_KEY
        }

        # Get all current tags this vulnerability has
        r = requests.get(url=endpoint, headers=header)
        vuln = json.loads(r.text)
        # print(vuln)
        current_tags = []
        for filter in vuln['filters']:
            current_tags.append(filter['label'])
        # print(current_tags)

        # Add the Github tag to the vulnerability
        current_tags.append("github-issue-created")
        endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "/tags/traces/bulk?expand=skip_links"
        payload = {
            "traces_uuid": [trace_uuid],
            "tags": current_tags,
            "tags_remove": []
        }
        r = requests.put(url=endpoint, json=payload, headers=header)
        verify = json.loads(r.text)
        # print(verify)

        # Add a comment to the vulnerabiity with a link to the Github issue
        app_endpoint = self.TEAMSERVER_BASE_URL + self.ORGANIZATION_UUID + "orgtraces/filter/%s" % trace_uuid
        r = requests.get(url=app_endpoint, headers=header)
        urls = json.loads(r.text)
        note_endpoint = ''
        for link in urls['trace']['links']:
            if link['rel'] == "add-note":
                note_endpoint = link['href']


        note_payload = {
            "note": "Github issue created for this vulnerability: %s" % issue_url
        }

        r = requests.post(url=note_endpoint, json=note_payload, headers=header)
        verify_comment = json.loads(r.text)
        # print(verify_comment)


# /Contrast/api/ng/e264d365-25e4-409e-a129-ec4c684c9d50/orgtraces/filter/Q6IU-HB9L-Q48T-Y5O9

github_controller = controller()

# github_controller.getuserinfo()

# github_controller.create_issue("title", "description")

# github_controller.list_issues()

# github_controller.get_assignees()

github_controller.get_teamserver_info()