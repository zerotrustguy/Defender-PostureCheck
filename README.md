Make sure you have all the relevant bindings such as 
1. KV Namespace - DEFENDER_KV
2. Policy_AUD - POLICY_AUD  [from your access application] as instructed in https://developers.cloudflare.com/cloudflare-one/identity/devices/service-providers/custom/
3. EXTERNAL_SERVICE_ENDPOINT - Your workers URL

Add the below as secrets using "wrangler secret put" command or from the workers dashboard.
1. MICROSOFT_CLIENT_ID
2. MICROSOFT_CLIENT_SECRET
3. MICROSOFT_TENANT_ID

Makes sure to install jose using "npm install jose" from your workers directory [iJavaScript module for JSON Object Signing and Encryption]

