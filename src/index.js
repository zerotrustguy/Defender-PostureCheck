/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

const jose = require('jose')

// Function to get or refresh Microsoft Defender access token
async function getDefenderAccessToken() {
  const kvKey = 'MICROSOFT_DEFENDER_TOKEN';
  const kvExpiryKey = 'MICROSOFT_DEFENDER_TOKEN_EXPIRY';

  const cachedToken = await DEFENDER_KV.get(kvKey);
  const cachedExpiry = await DEFENDER_KV.get(kvExpiryKey);
  const currentTime = Math.floor(Date.now() / 1000);

  if (cachedToken && cachedExpiry && parseInt(cachedExpiry) > currentTime + 300) {
    console.log('Using cached token');
    return cachedToken;
  }

  console.log('Refreshing Microsoft Defender token');
  const tokenEndpoint = `https://login.microsoftonline.com/${MICROSOFT_TENANT_ID}/oauth2/v2.0/token`;
  try {
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: MICROSOFT_CLIENT_ID,
        client_secret: MICROSOFT_CLIENT_SECRET,
        scope: 'https://api.securitycenter.microsoft.com/.default'
      }).toString()
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`Token refresh failed: ${response.status} ${response.statusText} - ${errorBody}`);
      throw new Error(`Token refresh failed: ${response.statusText} - ${errorBody}`);
    }

    const tokenData = await response.json();
    const newToken = tokenData.access_token;
    const expiresIn = tokenData.expires_in;
    const newExpiry = currentTime + expiresIn;

    console.log('Storing new token in KV');
    await DEFENDER_KV.put(kvKey, newToken);
    await DEFENDER_KV.put(kvExpiryKey, newExpiry.toString());

    return newToken;
  } catch (error) {
    console.error(`Token refresh error: ${error.message}`);
    throw error;
  }
}

// Function to fetch device data from Microsoft Defender API
async function fetchDefenderDeviceData() {
  const token = await getDefenderAccessToken();
  console.log('Fetching Defender device data');
  const response = await fetch('https://api.securitycenter.microsoft.com/api/machines', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error(`Defender API request failed: ${response.status} ${response.statusText} - ${errorBody}`);
    throw new Error(`Defender API request failed: ${response.statusText} - ${errorBody}`);
  }

  const data = await response.json();
  console.log(`Defender API returned ${data.value.length} devices`);
  console.log(`Defender devices: ${JSON.stringify(data.value.map(device => ({
    id: device.id,
    computerDnsName: device.computerDnsName,
    ipAddresses: device.ipAddresses,
    lastExternalIpAddress: device.lastExternalIpAddress,
    deviceTag: device.deviceTag,
    aadDeviceId: device.aadDeviceId,
    lastSeen: device.lastSeen
  })))}`);
  return data.value;
}

// Main function to compute posture scores
async function computePostureScores(devices) {
  try {
    const devicePosture = await fetchDefenderDeviceData();
    const evaluations = await evaluateDevices(devices, devicePosture);
    return evaluations;
  } catch (error) {
    console.error('Error fetching Defender data:', error.message);
    return {};
  }
}

/**
 * Matches Cloudflare devices with Microsoft Defender devices and assigns posture scores.
 * @param {Array} devices - Devices from Cloudflare
 * @param {Array} devicePosture - Device data from Microsoft Defender API
 * @returns {Object} - Map of device_id to { s2s_id, score }
 */
async function evaluateDevices(devices, devicePosture) {
  console.log('Evaluating devices');
  let evaluations = {};
  const matchedDefenderIds = new Set();
  const deviceSignatures = new Map();

  devices.forEach(device => {
    // Skip duplicates
    const signature = `${device.hostname}|${device.mac_address}|${device.serial_number}|${device.virtual_ipv4}`;
    if (deviceSignatures.has(signature)) {
      console.log(`Skipping duplicate device: ${JSON.stringify(device)}, previous device_id: ${deviceSignatures.get(signature)}`);
      evaluations[device.device_id] = { s2s_id: 'duplicate', score: 0 };
      return;
    }
    deviceSignatures.set(signature, device.device_id);

    console.log(`Matching device: ${JSON.stringify(device)}`);
    let matchingDefenderDevice = null;

    for (const defenderDevice of devicePosture) {
      if (matchedDefenderIds.has(defenderDevice.id)) {
        console.log(`Skipping already matched Defender device: ${defenderDevice.id}`);
        continue;
      }

      // Normalize hostname
      const normalizeHostname = (name) => name ? name.split('.')[0].toLowerCase() : '';
      const cfHostname = normalizeHostname(device.hostname);
      const defenderHostname = normalizeHostname(defenderDevice.computerDnsName);
      console.log(`Comparing hostname: cf=${cfHostname}, defender=${defenderHostname}`);

      // Normalize MAC address
      const normalizeMac = (mac) => mac ? mac.replace(/[:-]/g, '').toLowerCase() : '';
      const cfMac = normalizeMac(device.mac_address);
      const defenderMacs = defenderDevice.ipAddresses?.map(ip => normalizeMac(ip.macAddress)).filter(Boolean) || [];
      console.log(`Comparing mac_address: cf=${cfMac}, defender=${JSON.stringify(defenderMacs)}`);

      // Match by hostname
      if (cfHostname && cfHostname === defenderHostname) {
        console.log(`Matched by hostname: ${device.hostname} (normalized: ${cfHostname})`);
        matchingDefenderDevice = defenderDevice;
        break;
      }
      // Match by mac_address
      if (cfMac && defenderMacs.includes(cfMac)) {
        console.log(`Matched by mac_address: ${device.mac_address}`);
        matchingDefenderDevice = defenderDevice;
        break;
      }
      // Match by serial_number (last resort)
      if (device.serial_number && (
        defenderDevice.id === device.serial_number ||
        defenderDevice.deviceTag === device.serial_number ||
        defenderDevice.aadDeviceId === device.serial_number
      )) {
        console.log(`Matched by serial_number: ${device.serial_number}`);
        matchingDefenderDevice = defenderDevice;
        break;
      }
    }

    let score = 0;
    let s2s_id = 'unmatched';

    if (matchingDefenderDevice) {
      s2s_id = matchingDefenderDevice.id;
      matchedDefenderIds.add(s2s_id);
      const riskScore = matchingDefenderDevice.riskScore?.toLowerCase();
      const exposureLevel = matchingDefenderDevice.exposureLevel?.toLowerCase();

      if (riskScore === 'low' && exposureLevel === 'low') {
        score = 90;
      } else if (riskScore === 'medium' && exposureLevel === 'medium') {
        score = 60;
      //} else if (riskScore === 'high' || exposureLevel === 'high') {
       // score = 30;
	  } else if (riskScore === 'medium' && exposureLevel === 'high') {
        score = 53; //for test machine
      } else if (riskScore === 'none' && exposureLevel === 'medium') {
        score = 70;
      } else {
        score = 50;
      }
      console.log(`Assigned score: ${score} for s2s_id: ${s2s_id}, riskScore: ${riskScore}, exposureLevel: ${exposureLevel}`);
    } else {
      console.log(`No match found for device_id: ${device.device_id}`);
      console.log(`Checked: serial_number=${device.serial_number}, virtual_ipv4=${device.virtual_ipv4}, hostname=${device.hostname}, mac_address=${device.mac_address}`);
    }

    evaluations[device.device_id] = { s2s_id, score };
  });

  console.log(`Final evaluations: ${JSON.stringify(evaluations)}`);
  return evaluations;
}

// Request handler
async function handleExternalDevicePostureRequest(event) {
  try {
    const token = event.request.headers.get('Cf-Access-Jwt-Assertion');

    if (!token) {
      console.error('Missing Cf-Access-Jwt-Assertion header');
      return new Response(
        JSON.stringify({ success: false, error: 'missing required cf authorization token' }),
        {
          status: 403,
          headers: { 'content-type': 'application/json' },
        }
      );
    }

    const jwks = jose.createRemoteJWKSet(new URL(`https://${TEAM_DOMAIN}/cdn-cgi/access/certs`));
    try {
      await jose.jwtVerify(token, jwks, {
        audience: `${POLICY_AUD}`
      });
      console.log('JWT verification successful');
    } catch (e) {
      console.error(`JWT verification failed: ${e.message}`);
      return new Response(
        JSON.stringify({ success: false, error: `JWT verification failed: ${e.message}` }),
        {
          status: 403,
          headers: { 'content-type': 'application/json' },
        }
      );
    }

    const body = await event.request.json();
    console.log('Processing request body:', JSON.stringify(body));
    const resultBody = await computePostureScores(body.devices);

    return new Response(JSON.stringify({ result: resultBody }), {
      headers: { 'content-type': 'application/json' },
    });
  } catch (e) {
    console.error(`Request handler error: ${e.message}`);
    return new Response(
      JSON.stringify({ success: false, error: e.message }),
      {
        status: 500,
        headers: { 'content-type': 'application/json' },
      }
    );
  }
}

addEventListener('fetch', event => {
  event.respondWith(handleExternalDevicePostureRequest(event));
});