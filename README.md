# Contrast integration with Github

Use this plugin to send vulnerabilities to Github as issues.

### System Requirements:
- Python 3+
- Contrast teamserver account
- Github account

### Steps to run:
1. Tag all vulnerabilities in teamserver which you want to open a Github issue for.
2. Configure the following environment variables:
    - **CONTRAST_TEAMSERVER_URL**: The URL of the teamserver you're using ending with */Contrast/api/ng/*. For example, our SaaS server is at https://app.contrastsecurity.com/Contrast/api/ng/
    - **CONTRAST_ORGANIZATION_ID**: The organization ID of the teamserver you're using. You can find this 32-digit hash in the teamserver URL: https://app.contrastsecurity.com/Contrast/static/ng/index.html#/e264d963-25e4-j37d-a129-t63hd746/settings/
    - **CONTRAST_USERNAME**: The username you use to log in to the teamserver
    - **CONTRAST_API_KEY**: The API Key for your teamserver account. More details on how to get this: https://docs.contrastsecurity.com/tools-apiaccess.html
    - **CONTRAST_SERVICE_KEY**: The Service Key for your teamserver account. More details on how to get this: https://docs.contrastsecurity.com/tools-apiaccess.html
    - **CONTRAST_TEAMSERVER_TAG**: The tag you've applied to vulnerabilities which you want to open a Github issue for. 
    - **GITHUB_USERNAME** The username you use to login to Github.
    - **GITHUB_REPO_NAME:** The Github repository you'd like to open issues in.
    - **GITHUB_ACCESS_TOKEN**: Your Github personal access token. Steps on how to create one: https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/
3. Run ```python controller.py```
