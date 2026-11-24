// Worked example used to explain threat modelling: a deliberately small smart thermostat.
// Served as a practice assessment and rendered inside the STRIDE explainer.
import { newAssessment, newRisk, normalize } from './model.js';

export const TUTORIAL_ID = 'tutorial';
export const TUTORIAL_TITLE = 'Tutorial – Smart thermostat (threat-modelling practice)';

export const FOUR_QUESTIONS = [
  { q: 'What are we working on?', a: 'Draw the system: components, interfaces and who / what is on the other side of each interface.', step: 'Architecture & interfaces, Assets' },
  { q: 'What can go wrong?', a: 'Walk every element through the six STRIDE categories. Each answer is either a threat scenario or a reasoned "not applicable".', step: 'Threat identification (STRIDE)' },
  { q: 'What are we going to do about it?', a: 'Rate each scenario, define controls, map them to CRA Annex I and rate what is left (residual risk).', step: 'Risk method, Risk register, Annex I' },
  { q: 'Did we do a good job?', a: 'Every cell decided, every interface and asset covered, controls verified by tests, review when the design changes.', step: 'Checks, Review & approval' },
];

// One interface (I-03 BLE setup) walked through all six categories.
export const WALKTHROUGH = {
  element: 'I-03 – Bluetooth setup between phone and thermostat',
  context: 'During installation the app sends the home Wi-Fi password to the thermostat over Bluetooth LE and links the device to the user\'s account. The interface is active only in setup mode.',
  rows: [
    { letter: 'S', question: 'Can someone pretend to be the legitimate phone or device?',
      answer: 'A neighbour within radio range could pair with a thermostat that is in setup mode if the pairing PIN is fixed (e.g. 0000) and link it to their own account.',
      outcome: 'Threat → risk R-002', decision: 'risk' },
    { letter: 'T', question: 'Can data or commands on this interface be modified?',
      answer: 'An attacker could inject a different Wi-Fi network during setup. This is prevented by the same control as S: an authenticated, encrypted pairing.',
      outcome: 'Covered by R-002 (linked)', decision: 'risk' },
    { letter: 'R', question: 'Could actions be denied later or not be reconstructed?',
      answer: 'Setup performs no security-relevant action that has to be attributed later; the account binding itself is logged by the cloud (interface I-01).',
      outcome: 'Not applicable – justified', decision: 'na' },
    { letter: 'I', question: 'Can sensitive data leak?',
      answer: 'Yes – the home Wi-Fi password is transmitted. If BLE traffic is unencrypted it can be sniffed from outside the house.',
      outcome: 'Threat → risk R-003', decision: 'risk' },
    { letter: 'D', question: 'Can this interface be used to stop essential functions?',
      answer: 'Radio jamming only prevents setup; heating control keeps working with the last configuration. Impact negligible, the user can retry.',
      outcome: 'Not applicable – justified', decision: 'na' },
    { letter: 'E', question: 'Can someone gain more rights than intended?',
      answer: 'Re-entering setup mode on an installed device could take it over. Setup mode is only enabled by a physical button press – part of the R-002 control.',
      outcome: 'Covered by R-002 (linked)', decision: 'risk' },
  ],
  tips: [
    'Start with interfaces that cross a trust boundary to the outside (internet, radio, physical access) – that is where attackers enter.',
    'One risk may cover several cells (here R-002 covers S, T and E). Link it instead of writing duplicates.',
    'A good "not applicable" names the reason – what is missing for the threat to matter – not just "n/a" or "low risk".',
    'Do not rate yet. STRIDE finds the threats; likelihood × impact is decided afterwards in the risk register.',
  ],
};

export function tutorialAssessment() {
  const a = newAssessment({ title: TUTORIAL_TITLE, markets: ['consumer'] });
  Object.assign(a.product, {
    name: 'Smart thermostat ST-1 (tutorial)', model: 'ST-1', versions: 'HW rev A · FW 1.0 · App 1.0 · Cloud 2026.11',
    manufacturer: 'Example Ltd.', securityOwner: 'Product security owner',
    intendedPurpose: 'Controls a home heating system; schedules and target temperature set via mobile app; works locally without cloud.',
    foreseeableUse: 'Installed by consumers; weak or reused passwords; device resold with the house; setup left unfinished.',
    users: 'Owner (admin) · household members', environment: 'Private homes, consumer Wi-Fi router without IT management.',
    essentialFunctions: 'Heating control incl. frost protection; local operation without cloud.',
    safetyFunctions: 'Frost protection; maximum flow temperature enforced in firmware.', expectedLifetime: '10 years',
    rdps: 'Cloud service for remote control and schedules', personalData: 'Account e-mail, heating schedule (reveals presence)',
  });
  a.components = [
    { id: 'Z-1', name: 'Thermostat', description: 'Device with relay output to boiler, BLE + Wi-Fi', location: 'Home', operatedBy: 'Consumer', scope: 'Product (hardware/firmware)', slT: '', rationale: 'Controls heating', assumptions: '' },
    { id: 'Z-2', name: 'Cloud service', description: 'Device management, schedules, remote control, OTA', location: 'Cloud (EU)', operatedBy: 'Manufacturer', scope: 'Remote data processing (RDPS)', slT: '', rationale: 'Reaches the whole fleet', assumptions: '' },
    { id: 'Z-3', name: 'Mobile app', description: 'iOS / Android app', location: 'User phone', operatedBy: 'Consumer', scope: 'Product (software/app)', slT: '', rationale: '', assumptions: '' },
  ];
  a.interfaces = [
    { id: 'I-01', name: 'Device ↔ cloud', from: 'Z-1', to: 'Z-2', protocol: 'MQTT over TLS 8883, outbound', exposure: 'Internet', protection: 'Mutual TLS, per-device certificate', defaultState: 'Enabled', needed: 'Yes', remoteAccess: '', notes: '' },
    { id: 'I-02', name: 'App → cloud API', from: 'Z-3', to: 'Z-2', protocol: 'HTTPS 443', exposure: 'Internet', protection: 'OIDC login, optional MFA', defaultState: 'Enabled', needed: 'Yes', remoteAccess: '', notes: '' },
    { id: 'I-03', name: 'Bluetooth setup', from: 'Nearby phone', to: 'Z-1', protocol: 'BLE GATT', exposure: 'Radio range (BLE / Wi-Fi / Zigbee / LTE)', protection: 'Per-device setup code, LE Secure Connections', defaultState: 'Enabled during setup only', needed: 'Yes', remoteAccess: '', notes: 'Setup mode via button press' },
    { id: 'I-04', name: 'Debug UART', from: 'Person with the device', to: 'Z-1', protocol: 'UART header on PCB', exposure: 'Physical access to device', protection: 'Locked in production', defaultState: 'Disabled', needed: 'No', remoteAccess: '', notes: '' },
  ];
  a.assets = [
    { id: 'A-01', name: 'Heating control & frost protection', component: 'Z-1', type: 'Function (essential)', description: 'Schedules, set-points, frost protection', c: 'n/a', i: 'High', a: 'High', impact: 'Frozen pipes, discomfort, energy cost' },
    { id: 'A-02', name: 'Home Wi-Fi password', component: 'Z-1', type: 'Security asset', description: 'Stored on device after setup', c: 'High', i: 'Medium', a: 'n/a', impact: 'Access to the home network' },
    { id: 'A-03', name: 'Device identity key', component: 'Z-1', type: 'Security asset', description: 'Per-device key in secure element', c: 'High', i: 'High', a: 'Medium', impact: 'Device impersonation' },
    { id: 'A-04', name: 'User account', component: 'Z-2', type: 'Security asset', description: 'Credentials, sessions', c: 'High', i: 'High', a: 'Medium', impact: 'Remote control by attacker' },
    { id: 'A-05', name: 'Heating schedule', component: 'Z-2', type: 'Personal data', description: 'Reveals when the home is empty', c: 'High', i: 'Medium', a: 'Low', impact: 'Burglary targeting; GDPR' },
  ];
  const risk = (fields) => ({ ...newRisk(a), lastReviewed: '2026-11-23', ...fields });
  a.risks = [
    risk({ id: 'R-001', interfaces: 'I-02', assets: 'A-04, A-01', stride: 'S - Spoofing', actor: 'Credential-stuffing attacker', vector: 'App login',
      scenario: 'Account takeover with reused passwords; attacker switches heating off in winter.', consequence: 'Frost damage; user locked out',
      inherentL: 4, inherentI: 4, controls: 'Breached-password check; rate limiting; optional MFA; new-login notification; frost protection enforced in firmware.',
      annex: ['P1-2d', 'P1-2l'], en18031: ['AUM', 'ACM'], en303645: ['5.1'], residualL: 2, residualI: 3, status: 'Implemented', evidence: 'Pen-test report §3' }),
    risk({ id: 'R-002', interfaces: 'I-03', assets: 'A-02, A-01', stride: 'S - Spoofing', actor: 'Nearby attacker (radio range)', vector: 'BLE pairing in setup mode',
      scenario: 'Nearby attacker pairs with the thermostat using a fixed PIN, links it to their own account or injects a rogue Wi-Fi network.', consequence: 'Device hijacked; heating controlled by attacker',
      inherentL: 3, inherentI: 4, controls: 'Unique per-device setup code (QR on label); LE Secure Connections; setup mode only after physical button press, times out after 10 min.',
      annex: ['P1-2b', 'P1-2d'], en18031: ['AUM', 'SCM'], en303645: ['5.1', '5.5'], residualL: 1, residualI: 4, status: 'Verified', evidence: 'Test TC-BLE-01..04' }),
    risk({ id: 'R-003', interfaces: 'I-03', assets: 'A-02', stride: 'I - Information disclosure', actor: 'Nearby attacker (radio range)', vector: 'BLE sniffing',
      scenario: 'Home Wi-Fi password sniffed while it is sent to the thermostat during setup.', consequence: 'Access to the home network',
      inherentL: 3, inherentI: 3, controls: 'Wi-Fi credentials sent only over the encrypted, authenticated BLE channel (R-002); stored encrypted on device.',
      annex: ['P1-2e'], en18031: ['SCM', 'SSM'], en303645: ['5.5', '5.4'], residualL: 1, residualI: 3, status: 'Verified', evidence: 'BLE capture test TC-BLE-05' }),
    risk({ id: 'R-004', interfaces: 'I-01', assets: 'A-01, A-03', stride: 'T - Tampering', actor: 'External attacker (opportunistic)', vector: 'Network path',
      scenario: 'Man-in-the-middle alters commands between thermostat and cloud.', consequence: 'Wrong temperatures; heating off',
      inherentL: 3, inherentI: 4, controls: 'Mutual TLS 1.3 with per-device certificate; pinning to manufacturer CA.',
      annex: ['P1-2e', 'P1-2f'], en18031: ['SCM', 'CRY'], en303645: ['5.5'], residualL: 1, residualI: 4, status: 'Implemented', evidence: 'TLS scan' }),
    risk({ id: 'R-005', interfaces: 'Z-2', assets: 'A-05', stride: 'I - Information disclosure', actor: 'Opportunistic remote attacker / botnet', vector: 'Cloud database',
      scenario: 'Cloud breach exposes heating schedules showing when homes are empty.', consequence: 'Burglary targeting; GDPR breach',
      inherentL: 2, inherentI: 4, controls: 'Encryption at rest; schedules not linked to address; retention limits; access logging.',
      annex: ['P1-2e', 'P1-2g'], en18031: ['SSM'], en303645: ['5.8', '6'], residualL: 1, residualI: 4, status: 'In progress' }),
    risk({ id: 'R-006', interfaces: 'I-04', assets: 'A-03', stride: 'S - Spoofing', actor: 'External attacker (targeted / skilled)', vector: 'UART on a purchased unit',
      scenario: 'Debug port used to extract a key shared by all devices, allowing fleet-wide impersonation.', consequence: 'Fleet-wide compromise',
      inherentL: 2, inherentI: 5, controls: 'Per-device keys in secure element; UART locked in production; no shared secrets.',
      annex: ['P1-2e', 'P1-2j'], en18031: ['CCK', 'GEC'], en303645: ['5.4', '5.6'], residualL: 1, residualI: 3, status: 'Verified', evidence: 'Teardown test' }),
  ];
  // The worked interface I-03 is fully decided; other cells stay open to practise on.
  a.stride = {
    'I-03': {
      T: { refs: ['R-002'] }, E: { refs: ['R-002'] },
      R: { na: true, justification: 'Setup performs no security-relevant action needing attribution; account binding is logged in the cloud (I-01).' },
      D: { na: true, justification: 'Jamming only prevents setup; heating keeps running on the last configuration and the user can retry. Impact negligible.' },
    },
  };
  a.method.approvedBy = 'Tutorial'; a.method.approvedAt = '2026-11-23';
  a.supportPeriod = { ...a.supportPeriod, years: '10', endDate: '12/2036', rationale: 'Expected period of use of a heating controller is ~10 years.' };
  return normalize(a);
}

// Product components of the tutorial thermostat, with small example SBOMs (deliberately outdated
// packages so that the vulnerability lookup has something to find).
export function tutorialComponents() {
  const cdx = (root, version, comps) => ({
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { timestamp: '2026-11-01T08:00:00Z', tools: { components: [{ type: 'application', name: 'example-sbom-generator', version: '1.0' }] },
      component: { 'bom-ref': 'root', type: 'firmware', name: root, version } },
    components: comps.map((c, i) => ({ 'bom-ref': `c${i}`, type: 'library', ...c })),
    dependencies: [{ ref: 'root', dependsOn: comps.map((_, i) => `c${i}`) }],
  });
  return [
    { name: 'Thermostat firmware', type: 'firmware', version: '1.0.0', data: { description: 'Embedded Linux firmware of the ST-1 thermostat', assessmentRef: 'Z-1' },
      sbom: cdx('st1-firmware', '1.0.0', [
        { name: 'busybox', version: '1.31.1', cpe: 'cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*', supplier: { name: 'BusyBox project' }, licenses: [{ license: { id: 'GPL-2.0-only' } }] },
        { name: 'openssl', version: '1.1.1k', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*', purl: 'pkg:generic/openssl@1.1.1k', supplier: { name: 'OpenSSL Software Foundation' }, licenses: [{ license: { id: 'OpenSSL' } }] },
        { name: 'zlib', version: '1.2.11', cpe: 'cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*', supplier: { name: 'zlib project' }, licenses: [{ license: { id: 'Zlib' } }] },
      ]) },
    { name: 'Cloud service', type: 'backend', version: '2026.11', data: { description: 'Device management, schedules, remote control, OTA', assessmentRef: 'Z-2' },
      sbom: cdx('st1-cloud', '2026.11', [
        { name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1', supplier: { name: 'OpenJS Foundation' }, licenses: [{ license: { id: 'MIT' } }] },
        { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', supplier: { name: 'OpenJS Foundation' }, licenses: [{ license: { id: 'MIT' } }] },
        { name: 'jsonwebtoken', version: '8.5.1', purl: 'pkg:npm/jsonwebtoken@8.5.1', supplier: { name: 'Auth0' }, licenses: [{ license: { id: 'MIT' } }] },
      ]) },
    { name: 'Mobile app', type: 'mobile', version: '1.0', data: { description: 'iOS / Android app', assessmentRef: 'Z-3' } },
    { name: 'Thermostat hardware', type: 'hardware', version: 'rev A', data: { description: 'Main PCB with relay output, BLE and Wi-Fi module' } },
  ];
}
