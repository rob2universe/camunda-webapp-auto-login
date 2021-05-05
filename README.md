# Camunda Web Application SSO / auto-login Filter example

Mostly copied from [camunda-webapp-plugin-sso-autologin](https://github.com/camunda-consulting/camunda-webapp-plugins/tree/master/camunda-webapp-plugin-sso-autologin)  
Minor modification and adjustment of  process engine lookup for Spring Boot environment.
Authenticates a request against the process engine's identity service  getting the user id 
from the url parameter *auto-login-username*
Example request: http://localhost:8080/camunda/app/tasklist/default/?auto-login-username=demo
This is an example for the baseline setup meant to be extended with a custom security mechanism.
THIS IS A SECURITY ISSUE. DO NOT USE AS IS IN PRODUCTION.