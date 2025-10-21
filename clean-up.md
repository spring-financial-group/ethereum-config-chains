# 🧭 Clearing up the private network on OSS Playground 

## If you want to try this from scratch inform everyone on Slack (Block chain channels) that you are going to do this an uninstall everythign and re-deploy 

'''bash

helm list -n devnet

'''

Then just 

''' bash

helm uninstall XXX

'''

All the helm files from the helm list

Delete the postgress PVC to clear the DB's up (They will be re-created as part of the installs)

'''bash

kubectl delete pvc data-blockscout-db-postgresql-0

'''

And that shoudl be a clean envionment to start from scratch.

## This is IMPORTANT if you use the config files from this repo be aware that these will have a Genesis time of the last tiem they were created if they were created in the past then there will be too much drift and blocks to catch up , so the validator will often time out , all you need to do is make sure you do the kurtosis steps and re-create the config files and make sure you push them back up to this repo (as this repo is used by the helm charts) and produce the keys and secrets.

## Basically do all the steps but make sure afetr the kurtosis steps you push back to main on this repo as they are the files you will be using


