# GreenOrbit API Application using the Serverless Framework

To get an insight into the overall concept, read Gavin's blog posts:
- Lambda Authorizers: https://medium.com/faun/securing-api-gateway-with-lambda-authorizers-62845032bc7d
- GreenOrbit/iD SSO concept: http://help.intranetdashboard.com/systemadmin/Utilities/single_sign_on/SingleSignOn.html
- CI/CD Pipeline Concept: https://medium.com/faun/how-to-build-a-serverless-ci-cd-pipeline-on-aws-907be91c2e48

This is the completed boilerplate including the Lambda Authorizer function to take the SSO token from iD/GO, then use it to generate a JWT which then should be stored in the user’s browser and then used for subsequent API requests.  Here is an overview of what is included:

There are 6 new files in the Authorizer Folder – these files at a really high level handle reading of the SSO token from iD/GO, decrypt it and then generate a JWT, along with the functionality required to validate the JWT on subsequent requests:
 
Serverless.yml contains two new functions:
-	authorizerCheckToken: This is the Lambda function which validates the JWT on each request to API Gateway.  
-	authorizerAuthenticate: This is the Lambda function which takes the iD SSO Token and then generates the JWT

and several new environment variables.
