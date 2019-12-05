# nodebb-plugin-cas
Nodebb plugin for SSO/SLO via Apereo CAS 

Specify these Urls in plugin.json

Param | Description 
--- | --- 
nodeBBUrl | Nodebb login endpoint, same as the service param in CAS login URI
CASServerPrefix | Apereo CAS server prefix
userCenterPrefix | User register endpoint

Example
```
{
  "nodeBBUrl": "http://localhost:4567/cas/login",
  "CASServerPrefix": "http://localhost:8443/cas",
  "userCenterPrefix": "http://localhost:8080/ctoms-v3/default/showreg"
}
```
