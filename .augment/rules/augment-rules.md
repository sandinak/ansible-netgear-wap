---
type: "manual"
---

- never try to use SSH to manage config
- always use the results of the analysis tool to find the path forward, if you find an endpoint that's not understood the analysis tool should be updated to explore and support it
- the scripts should as closely replicate what is done via the webui .. no short cuts but not use a browser
- the objective is to build an ansible module that manages the config of these APs