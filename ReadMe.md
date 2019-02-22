# Authentication Service

Service to validate a users credentials and then provide a signed JWT, this can then be used by other services to validate user identity and carry non-sensitive user information.

Implemented as a Node Express API, expected to be run on AWS Lambda. template.yml contains a AWS SAM template script that will deploy the service stack to a AWS environment.


## Functionality

When a user submits a post request with there login credentials to the login endpoint they will be issued with a    signed JWT with there user details. This JWT can then be used by external services for user based activities.

Example JWT payload generated for a logged in user:

```
{
  "iat": 1537299818,
  "iss": "authenticationService",
  "exp": 1537303418,
  "userID": "a6029410-b888-11e8-96fe-b7125766d434",
  "email": "ro5635@gmail.com",
  "firstName": "Robert",
  "lastName": "Curran",
  "age": "22",
  "rights": {
    "userControl": {
      "accountCreate": 1
    },
    "MachineAccess": {
      "create": 1,
      "update": 1,
      "read": 1,
      "delete": 1
    }
  },
  "jwtPayload": {
    "cake": "yummy"
  }
}
```

The key fields are the Rights JSON object, which can detail the users rights to services and the JWT Payload that can carry any additional data payload required for a user as a JSON object.

Core functionality is now in place, however there are still a number of points that are awaiting development. These are listed in the Github issues tracker.

Users can be created by users with the userControl createAccount right and submit an API request as listed in the postman docs linked below.

[Post Man Docs](https://documenter.getpostman.com/view/1268576/RWaLwTqq)

## Structure

This project is written as an express API and intended to be deployed to AWS using SAM (Serverless Application Model), this will create the resources necessary to create the stack (dynamoDB tables, API gateway, Lambdas ETC) automatically.



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
These environment variables are supplied in the deployment to AWS as per the CloudFormation template in template.yml

AUTH_JWT_SECRET=EggsAndHamAreNice
USERSTABLE=
USERSEVENTSTABLE=

```
node bin\devRunner.js
```