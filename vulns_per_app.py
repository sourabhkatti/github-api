import base64
import requests
import json


class vuln_farmer:
    base_url = "https://app.contrastsecurity.com/Contrast/api/ng/"
    username = "sourabh.katti@contrastsecurity.com"
    api_key = "vgy5soZn15wnVPHH539pF8F7niofbl4N"
    service_key = "4K5V00T6JB90KPAD"
    organization_id = "142bb017-de7e-4af7-b5b9-f0782aa6d369"

    # username = "danielan@us.ibm.com"
    # api_key = "vgy5soZn15wnVPHH539pF8F7niofbl4N"
    # service_key = "4K5V00T6JB90KPAD"
    # organization_id = "142bb017-de7e-4af7-b5b9-f0782aa6d369"

    authorization = base64.b64encode((username + ':' + service_key).encode('utf-8'))
    header = {
        'Authorization': authorization,
        'API-Key': api_key
    }
    applications_vulns = {}

    def run(self):
        self.get_application_ids()
        self.get_application_trace_breakdown()
        self.get_application_trace_rule_breakdown()
        self.output_to_csv()

    def get_application_ids(self):
        url = self.base_url + self.organization_id + '/applications'

        response = requests.get(url=url, headers=self.header)
        applications = json.loads(response.text)
        for application in applications['applications']:
            self.applications_vulns[application['app_id']] = {'name': application['name']}
        print("Found %d applications. Starting breakdown." % self.applications_vulns.keys().__len__())

    def get_application_trace_breakdown(self):
        i = 1
        print("\n\nGetting trace breakdown per application")
        for app_id, app_obj in self.applications_vulns.items():
            print("%d. %s" % (i, app_obj['name']))
            url = self.base_url + self.organization_id + '/applications/' + app_id + '/breakdown/trace'
            # /ng/{orgUuid}/applications/{appId}/breakdown/trace
            response = requests.get(url=url, headers=self.header)
            trace_breakdown = json.loads(response.text)
            app_obj.update({'trace_breakdown': trace_breakdown['trace_breakdown']})
            i += 1
        print("Trace breakdown done!\n")

    def get_application_trace_rule_breakdown(self):
        i = 1
        print("\nGetting rule breakdown per application")
        for app_id, app_obj in self.applications_vulns.items():
            print("%d. %s" % (i, app_obj['name']))
            rule_counts = {}
            for environment in ('DEVELOPMENT', "QA", "PRODUCTION"):
                url = self.base_url + self.organization_id + "/applications/" + app_id + "/breakdown/trace/rule?environment=" + environment
                # https://app.contrastsecurity.com/Contrast/api/ng/e264d365-25e4-409e-a129-ec4c684c9d50/applications/513795c8-b5c6-477f-ab36-3aaf37033b4e/
                # breakdown/trace/rule?environment=DEVELOPMENT
                response = requests.get(url=url, headers=self.header)
                trace_by_rules = json.loads(response.text)
                for trace in trace_by_rules['traces_breakdown']:
                    title = trace['rule_title']
                    if title in rule_counts.keys():
                        if trace['traces'] > rule_counts[title]:
                            rule_counts[title] = trace['traces']
                        # rule_counts[title] += trace['traces']
                    else:
                        rule_counts[title] = trace['traces']
            app_obj.update({"rule_breakdown": rule_counts})
            i += 1
        print("Rule breakdown done!\n")

    def output_to_csv(self):
        filename = 'application_breakdown.csv'
        print("\nStarting write to %s" % filename)
        csvfile = open(filename, 'w')
        line_to_write = '0,'
        app_obj = list(self.applications_vulns.values())[0]
        for trace_breakdown in app_obj['trace_breakdown']:
            line_to_write += str(trace_breakdown) + ','
        for rule_breakdown in app_obj['rule_breakdown']:
            line_to_write += str(rule_breakdown) + ','
        csvfile.write(line_to_write + '\n')

        for app_id, app_obj in self.applications_vulns.items():
            line_to_write = ""
            line_to_write += app_obj['name'] + ','
            print("\tWriting %s" % app_obj['name'])
            for trace_breakdown, counts in app_obj['trace_breakdown'].items():
                line_to_write += str(counts) + ','
            for rule_breakdown, counts in app_obj['rule_breakdown'].items():
                line_to_write += str(counts) + ','
            csvfile.write(line_to_write + '\n')










vuln_farmer = vuln_farmer()
vuln_farmer.run()
