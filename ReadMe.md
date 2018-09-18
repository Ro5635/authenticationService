# Authentication Service

Service to validate a users credentials and then provide a signed JWT, this can then be used by other services to validate user identity and carry non-sensitive user information.

Implemented as a Node Express API, expected to be run on AWS Lambda. template.yml contains a AWS SAM template script that will deploy the service stack to a AWS environment.


[Post Man Docs](https://documenter.getpostman.com/view/1268576/RWaLwTqq)

## Running Locally:

To run locally npm install and then run natively on the local node environment or use AWS SAM.

#### AWS SAM:

AWS SAM local can mount the project into a docker image for executing locally.

To do this install AWS SAM and in the root directory of the project and execute:
```
sam local start-api
```

### Node locally:

To run service on the local node runtime ensure to set the following environment variables and execute the below command.

AUTH_JWT_SECRET=EggsAndHamAreNice

```
node bin\devRunner.js
```