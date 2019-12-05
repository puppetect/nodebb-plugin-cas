# nodebb-plugin-cas
Nodebb plugin for SSO/SLO via Apereo CAS 

## Install
```
npm install nodebb-plugin-cas
```
Check [NodeBB docs](https://docs.nodebb.org/configuring/plugins/) for more detail

## Usage

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
## Reference
kwnetzwelt/[nodebb-plugin-gslogin](https://github.com/kwnetzwelt/nodebb-plugin-gslogin) </br>
ld000/[nodebb-plugin-cas](https://github.com/ld000/nodebb-plugin-cas)
