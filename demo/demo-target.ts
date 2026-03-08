// @ts-nocheck
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import https from 'https';

const app = express();

/**
 * ⚠️ VULNERABILITY 1: CORS Wildcard
 * Allows any origin to access the API.
 */
app.use(cors({ origin: '*' }));

/**
 * ⚠️ VULNERABILITY 2: Unencrypted Transport
 * Serving sensitive data over HTTP instead of HTTPS.
 */
const API_URL = "http://api.patientportal.com/v1";

app.post('/api/patients', (req, res) => {
    const data = req.body;

    // ⚠️ VULNERABILITY 3: Direct PHI Variable Assignment
    const patientSSN = data.socialSecurityNumber;
    const mrn = data.medicalRecordNumber;
    const dob = data.dateOfBirth;

    // ⚠️ VULNERABILITY 4: PHI Exposure in Logs
    console.log(`[POST] Creating new patient record for ${patientSSN}`);
    console.log(`Patient medical tracking active: DOB ${dob}, MRN ${mrn}`);

    // ⚠️ VULNERABILITY 5: Weak TLS Cipher configuration
    const legacyAgent = new https.Agent({
        secureProtocol: "TLSv1_method"
    });

    // Simulated API call sending PHI over legacy TLS
    https.get(`${API_URL}/register?ssn=${patientSSN}`, { agent: legacyAgent }, (response) => {
        res.json({ success: true, ssn: patientSSN, mrn: mrn });
    });
});

app.listen(8080, () => console.log('Medical API running on port 8080'));
