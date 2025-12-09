# Leverage AI for Vulnerability Management
Securing cloud infrastructure is a never-ending race between security teams and attackers. While tools like Amazon Inspector scan for vulnerabilities, their findings may provide only vague suggestions for remediation.

This project leverage LLMs to explain and remediate Inspector vulnerability findings for AWS EC2 instances. Specifically, new Inspector findings trigger Lambda functions, which normalize the finding details, call LLMs for remediation recommendations, and route the findings and recommendations to vulnerability managers using SNS. 

The repo includes both the necessary cloud architecture (`terraform/`) and code (`lambda/`).
